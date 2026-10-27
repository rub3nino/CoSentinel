"""sqlmap adapter — SQL injection, the way a human tester probes for it.

This is the first adapter that lives in the *active* half of the intensity
scale, so its window starts at AGGRESSIVE: it never fires in a SAFE scan.

  * AGGRESSIVE (detection): send boolean/time/error/UNION payloads into the
    target's parameters and forms and report *where* it is injectable. It does
    not read your data.
  * EXPLOIT (lab-only): additionally prove impact — fetch the DBMS banner,
    current user/database, DBA status and the list of databases. It still does
    not dump table contents; proving reachability of the data is the point, not
    exfiltrating it.

sqlmap has no stable machine-readable report, so we parse its (deterministic,
with --flush-session) stdout. The parser is unit-tested against real output.
"""

from __future__ import annotations

import re

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

# One "Parameter: <name> (<METHOD>)" header per injectable parameter.
_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<method>[^)]+)\)\s*$", re.M)
_TITLE_RE = re.compile(r"^\s*Title:\s*(?P<title>.+?)\s*$", re.M)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+?)\s*$", re.M)
_NOT_VULN = (
    "all tested parameters do not appear to be injectable",
    "does not seem to be injectable",
)
_UNREACHABLE = (
    "unable to connect to the target url",
    "unable to connect to the target",
    "connection timed out to the target url",
)
# EXPLOIT-tier proof-of-impact lines we surface verbatim.
_IMPACT_RE = {
    "banner": re.compile(r"^banner:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user": re.compile(r"^current user:\s*'(?P<v>.+?)'\s*$", re.M),
    "current database": re.compile(r"^current database:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user is DBA": re.compile(r"^current user is DBA:\s*(?P<v>\w+)\s*$", re.M),
}


@register
class SqlmapAdapter(Adapter):
    name = "sqlmap"
    requires_tool = "sqlmap"
    runs_on = "scanner"
    min_intensity = Intensity.AGGRESSIVE   # active injection — never in a SAFE scan
    max_intensity = Intensity.EXPLOIT

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        argv = [
            "sqlmap",
            "-u", target.web_target,
            "--batch",            # never prompt — fully non-interactive
            "--disable-coloring",
            "--flush-session",    # fresh results each run (deterministic output)
            "--random-agent",
            "--forms",            # also test HTML forms, not just the URL query
            "--crawl=2",          # discover a couple of levels of links to test
            "--level=3", "--risk=2",   # deeper payload set than the default
        ]
        label = "sqlmap injection detection"
        if intensity >= Intensity.EXPLOIT:
            # Prove impact without dumping user data: identify the DBMS and the
            # account/database the injection reaches, and whether it is DBA.
            argv += ["--banner", "--current-user", "--current-db", "--is-dba", "--dbs"]
            label = "sqlmap injection + impact (lab)"
        return [PlannedCommand(argv=argv, timeout=1800, label=label)]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        res = results[0] if results else None
        out = (res.stdout if res else "") or ""
        low = out.lower()
        where = target.web_target

        if not out.strip():
            msg = (res.stderr.strip() if res else "") or "sqlmap produced no output"
            return [self._info("sqlmap produced no output", msg, target)]

        if any(s in low for s in _UNREACHABLE):
            return [self._info("sqlmap could not reach the target", where, target)]

        params = list(_PARAM_RE.finditer(out))
        if not params:
            if any(s in low for s in _NOT_VULN):
                return [self._info("sqlmap: no SQL injection found", where, target)]
            return [self._info("sqlmap: no injectable parameters tested", where, target)]

        dbms_m = _DBMS_RE.search(out)
        dbms = dbms_m.group("dbms").strip() if dbms_m else "unknown DBMS"

        # One finding per injectable parameter, with the techniques that worked.
        findings: list[Finding] = []
        bounds = [m.start() for m in params] + [len(out)]
        for i, m in enumerate(params):
            name = m.group("name").strip()
            method = m.group("method").strip()
            segment = out[bounds[i]:bounds[i + 1]]
            titles = [t.group("title").strip() for t in _TITLE_RE.finditer(segment)]
            findings.append(Finding(
                source=self.name, target=target.id, severity=Severity.HIGH,
                category=Category.VULNERABILITY,
                title=f"SQL injection in parameter '{name}' ({method})",
                resource=f"{where} (param: {name} [{method}])",
                description=f"Injectable against {dbms}. Techniques confirmed: "
                            + ("; ".join(titles) if titles else "see sqlmap output") + ".",
                remediation="Use parameterized queries / prepared statements; validate and "
                            "escape input; apply least-privilege to the DB account.",
                references=["CWE-89"],
                raw={"dbms": dbms, "method": method, "titles": titles},
            ))

        # EXPLOIT tier: a single CRITICAL proof-of-impact finding if sqlmap
        # actually reached the DBMS identity/data.
        impact = {k: rx.search(out) for k, rx in _IMPACT_RE.items()}
        impact = {k: m.group("v") for k, m in impact.items() if m}
        dbs = self._databases(out)
        if impact or dbs:
            details = "; ".join(f"{k}: {v}" for k, v in impact.items())
            if dbs:
                details += ("; " if details else "") + f"databases: {', '.join(dbs)}"
            findings.append(Finding(
                source=self.name, target=target.id, severity=Severity.CRITICAL,
                category=Category.VULNERABILITY,
                title="SQL injection confirmed exploitable (DBMS access proven)",
                resource=where,
                description="sqlmap reached the database through the injection: " + details + ".",
                remediation="Treat as an active breach path: fix the injection immediately and "
                            "review DB access logs and account privileges.",
                references=["CWE-89"],
                raw={"impact": impact, "databases": dbs},
            ))
        return findings

    @staticmethod
    def _databases(out: str) -> list[str]:
        """Parse the 'available databases [N]:' block into a list of names."""
        m = re.search(r"available databases \[\d+\]:\s*\n(?P<body>(?:\[\*\].+\n?)+)", out)
        if not m:
            return []
        return [line[3:].strip() for line in m.group("body").splitlines()
                if line.startswith("[*]")]

    @staticmethod
    def _info(title: str, detail: str, target: Target) -> Finding:
        return Finding(source="sqlmap", target=target.id, severity=Severity.INFO,
                       category=Category.INFO, title=title, description=detail,
                       resource=target.web_target)
