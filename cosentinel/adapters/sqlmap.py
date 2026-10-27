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

**Anti-CSRF forms (Laravel, Rails, …).** Many login forms carry a hidden,
per-request token (`_token` in Laravel) and reject any POST without a fresh
one, so a naive `--forms` run never actually tests the form. We tell sqlmap the
token field name (``--csrf-token``) so it re-reads a fresh token before each
attack request; the name defaults to Laravel's ``_token`` and is overridable
(``COSENTINEL_SQLMAP_CSRF_TOKEN`` — set it empty to disable). If the token must
be fetched from a different page than the one under test, point
``COSENTINEL_SQLMAP_CSRF_URL`` at it.

sqlmap has no stable machine-readable report, so we parse its (deterministic,
with --flush-session) stdout. The parser is unit-tested against real output.

**Why the outcome classification is careful.** sqlmap says many different
things, and they are not all equal. "reached the target and found it clean" is
a very different result from "never reached the target at all" — reporting the
first as the second hides a *missing* test behind a reassuring-looking INFO.
And with ``--crawl`` a *secondary* link can fail to connect (logged at
``[WARNING]``) while the primary target was reached and fully tested — that must
not be mistaken for the whole target being down. So we only call it unreachable
on a ``[critical]`` connection failure *and* no evidence the target was ever
fetched.
"""

from __future__ import annotations

import os
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

# Reached + tested, nothing injectable.
_NOT_VULN = (
    "all tested parameters do not appear to be injectable",
    "does not seem to be injectable",
)
# Reached, but there was nothing to test (no form / no parameter / no links).
_NO_TESTABLE = (
    "there were no forms found at the given target url",
    "no parameter(s) found for testing",
    "no usable links found",
    "all testable parameters you provided are not present within the given request data",
)
# A *fatal* connection failure to the primary target: sqlmap logs these at
# [critical] and aborts. A mid-crawl "[WARNING] unable to connect" to a
# secondary link is deliberately NOT in here — see the module docstring.
_FATAL_UNREACH = re.compile(
    r"\[critical\][^\n]*(?:"
    r"unable to connect to the target url"
    r"|connection timed out to the target url"
    r"|unable to connect to the target url or proxy)",
    re.I,
)
# Any line that proves sqlmap actually fetched the target at least once. If we
# see one of these, a later connection error was to a crawled/secondary URL,
# not the target itself.
_REACHED_SIGNALS = (
    "detected web page charset",
    "starting crawler for target url",
    "got a 301 redirect",
    "got a 302 redirect",
    "got a 303 redirect",
    "got a 307 redirect",
    "target url content is stable",
    "web application technology",
    "back-end dbms",
    "found a hidden csrf token",
    "csrf token parameter",
)
# EXPLOIT-tier proof-of-impact lines we surface verbatim.
_IMPACT_RE = {
    "banner": re.compile(r"^banner:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user": re.compile(r"^current user:\s*'(?P<v>.+?)'\s*$", re.M),
    "current database": re.compile(r"^current database:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user is DBA": re.compile(r"^current user is DBA:\s*(?P<v>\w+)\s*$", re.M),
}

_CSRF_TOKEN_ENV = "COSENTINEL_SQLMAP_CSRF_TOKEN"
_CSRF_URL_ENV = "COSENTINEL_SQLMAP_CSRF_URL"
_CSRF_TOKEN_DEFAULT = "_token"   # Laravel; set the env to "" to disable


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
        ]
        # Re-read a fresh anti-CSRF token before each attack so form apps
        # (Laravel's `_token`, …) are actually testable instead of silently
        # rejected. Empty env disables it; a separate token page is optional.
        csrf_token = os.environ.get(_CSRF_TOKEN_ENV, _CSRF_TOKEN_DEFAULT)
        if csrf_token:
            argv.append(f"--csrf-token={csrf_token}")
            csrf_url = os.environ.get(_CSRF_URL_ENV, "")
            if csrf_url:
                argv.append(f"--csrf-url={csrf_url}")
        argv += ["--level=3", "--risk=2"]   # deeper payload set than the default
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
            return [self._info("sqlmap produced no output", msg, target, out)]

        # 1) Injectable parameters win over everything else.
        params = list(_PARAM_RE.finditer(out))
        if params:
            return self._vulnerabilities(out, params, target, intensity)

        reached = any(s in low for s in _REACHED_SIGNALS)
        fatal_unreach = _FATAL_UNREACH.search(out)

        # 2) Genuinely never reached the target: a critical connect failure and
        #    no sign we ever fetched a page. This is a *missing* test, not a
        #    clean result — keep it clearly distinct.
        if fatal_unreach and not reached:
            line = fatal_unreach.group(0).strip()
            return [self._info("sqlmap could not reach the target",
                               f"{where} — {line}", target, out)]

        # 3) Reached and tested, but nothing was injectable.
        if any(s in low for s in _NOT_VULN):
            return [self._info("sqlmap: no SQL injection found", where, target, out)]

        # 4) Reached, but there was nothing to test (no form/params/links).
        if any(s in low for s in _NO_TESTABLE):
            return [self._info("sqlmap: no testable parameters or forms",
                               where, target, out)]

        # 5) A connect failure after we had already reached the target: a
        #    crawled/secondary link was down. The target itself was tested.
        if fatal_unreach:
            return [self._info("sqlmap: no SQL injection found",
                               f"{where} (a crawled link was unreachable)", target, out)]

        # 6) Anything else: sqlmap ran but drew no clear conclusion we recognize.
        return [self._info("sqlmap: no injectable parameters tested", where, target, out)]

    def _vulnerabilities(
        self, out: str, params: list[re.Match], target: Target, intensity: Intensity
    ) -> list[Finding]:
        where = target.web_target
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
    def _info(title: str, detail: str, target: Target, out: str = "") -> Finding:
        # Keep a short stdout tail so an unexpected outcome can be diagnosed
        # without re-running the whole scan (the old INFO findings stored {}).
        tail = out.strip()[-800:] if out else ""
        return Finding(source="sqlmap", target=target.id, severity=Severity.INFO,
                       category=Category.INFO, title=title, description=detail,
                       resource=target.web_target, raw={"stdout_tail": tail} if tail else {})
