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

**Rate-limiting and time-based false positives.** A *time-based* injection is
inferred purely from how long the server takes to answer a ``SLEEP`` payload.
When the target rate-limits (HTTP 429, throttling, a WAF dropping requests) the
response times go erratic, and sqlmap routinely mistakes that jitter for a
successful ``SLEEP`` — a false positive. Reporting that as a confirmed HIGH
("actively confirmed exploitable", +10 to the risk score) would be actively
misleading. So:

  * We detect rate-limiting in sqlmap's own output.
  * A parameter whose injection is confirmed *only* by time-based techniques,
    while rate-limiting was seen, is **downgraded to a MEDIUM "suspected"**
    finding instead of a HIGH confirmed one (which keeps it out of the
    "actively confirmed" boost).
  * ``scan()`` then automatically re-tests just that parameter with a
    ``--delay`` to defeat the timing noise, and reconciles: a clean-timing run
    that still flags it promotes it back to a real HIGH; one that clears it
    replaces the suspicion with an INFO "not confirmed (rate-limit false
    positive)". Set ``COSENTINEL_SQLMAP_AUTOVERIFY=0`` to skip the re-run (the
    finding then simply stays the MEDIUM suspicion), or
    ``COSENTINEL_SQLMAP_DELAY`` to apply a delay from the very first pass.

**Why the outcome classification is careful.** sqlmap says many different
things, and they are not all equal. "reached the target and found it clean" is
a very different result from "never reached the target at all" — reporting the
first as the second hides a *missing* test behind a reassuring-looking INFO.
And with ``--crawl`` a *secondary* link can fail to connect (logged at
``[WARNING]``) while the primary target was reached and fully tested — that must
not be mistaken for the whole target being down. So we only call it unreachable
on a ``[critical]`` connection failure *and* no evidence the target was ever
fetched.

sqlmap has no stable machine-readable report, so we parse its (deterministic,
with --flush-session) stdout. The parser is unit-tested against real output.
"""

from __future__ import annotations

import os
import re

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult, Runner
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
# Any line that proves sqlmap actually fetched the target at least once.
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
# The target (or a WAF in front of it) is throttling — the condition under which
# time-based results become unreliable.
_RATE_LIMITED = (
    "rate-limiting requests",
    "429 (too many requests)",
    "is dropping 'suspicious' requests",
)
# Injection techniques inferred from *timing* alone (false-positive-prone under
# rate-limiting). Everything else (boolean/error/UNION) is evidence-derived.
_TIME_BASED_MARKERS = ("time-based", "sleep", "heavy query", "benchmark")

# EXPLOIT-tier proof-of-impact lines we surface verbatim.
_IMPACT_RE = {
    "banner": re.compile(r"^banner:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user": re.compile(r"^current user:\s*'(?P<v>.+?)'\s*$", re.M),
    "current database": re.compile(r"^current database:\s*'(?P<v>.+?)'\s*$", re.M),
    "current user is DBA": re.compile(r"^current user is DBA:\s*(?P<v>\w+)\s*$", re.M),
}

_CSRF_TOKEN_ENV = "COSENTINEL_SQLMAP_CSRF_TOKEN"
_CSRF_URL_ENV = "COSENTINEL_SQLMAP_CSRF_URL"
_CSRF_TOKEN_DEFAULT = "_token"      # Laravel; set the env to "" to disable
_DELAY_ENV = "COSENTINEL_SQLMAP_DELAY"        # seconds between requests (proactive)
_AUTOVERIFY_ENV = "COSENTINEL_SQLMAP_AUTOVERIFY"   # "0" disables the re-run
_VERIFY_DELAY_DEFAULT = "1"
_VERIFY_TIMEOUT = 3600              # a delayed single-param re-run is slow


def _is_time_based(title: str) -> bool:
    t = title.lower()
    return any(k in t for k in _TIME_BASED_MARKERS)


@register
class SqlmapAdapter(Adapter):
    name = "sqlmap"
    requires_tool = "sqlmap"
    runs_on = "scanner"
    min_intensity = Intensity.AGGRESSIVE   # active injection — never in a SAFE scan
    max_intensity = Intensity.EXPLOIT

    # -- command building -------------------------------------------------
    def _argv(
        self, target: Target, intensity: Intensity, *,
        delay: str | None = None, only_params: str | None = None,
    ) -> list[str]:
        argv = [
            "sqlmap",
            "-u", target.web_target,
            "--batch",            # never prompt — fully non-interactive
            "--disable-coloring",
            "--flush-session",    # fresh results each run (deterministic output)
            "--random-agent",
            "--forms",            # also test HTML forms, not just the URL query
        ]
        # A focused re-test knows which parameter to hit, so it skips crawling.
        if not only_params:
            argv.append("--crawl=2")
        # Re-read a fresh anti-CSRF token before each attack so form apps
        # (Laravel's `_token`, …) are actually testable instead of silently
        # rejected. Empty env disables it; a separate token page is optional.
        csrf_token = os.environ.get(_CSRF_TOKEN_ENV, _CSRF_TOKEN_DEFAULT)
        if csrf_token:
            argv.append(f"--csrf-token={csrf_token}")
            csrf_url = os.environ.get(_CSRF_URL_ENV, "")
            if csrf_url:
                argv.append(f"--csrf-url={csrf_url}")
        if only_params:
            argv += ["-p", only_params]
        if delay:
            # Space requests out so a rate-limiter does not distort timing (and
            # poison time-based detection). This is the knob the auto-verify
            # re-run turns up; set it proactively via COSENTINEL_SQLMAP_DELAY.
            argv.append(f"--delay={delay}")
        argv += ["--level=3", "--risk=2"]   # deeper payload set than the default
        if intensity >= Intensity.EXPLOIT:
            # Prove impact without dumping user data: identify the DBMS and the
            # account/database the injection reaches, and whether it is DBA.
            argv += ["--banner", "--current-user", "--current-db", "--is-dba", "--dbs"]
        return argv

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        delay = os.environ.get(_DELAY_ENV) or None
        argv = self._argv(target, intensity, delay=delay)
        label = "sqlmap injection + impact (lab)" if intensity >= Intensity.EXPLOIT \
            else "sqlmap injection detection"
        if delay:
            label += f" (delay {delay}s)"
        return [PlannedCommand(argv=argv, timeout=1800, label=label)]

    # -- orchestration (overridden to add the auto-verify re-run) ---------
    def scan(self, runner: Runner, target: Target, intensity: Intensity) -> list[Finding]:
        results = [runner.run(pc.argv, timeout=pc.timeout, sudo=pc.sudo)
                   for pc in self.plan(target, intensity)]
        findings = self.parse(results, target, intensity)

        if os.environ.get(_AUTOVERIFY_ENV, "1") == "0":
            return findings
        # A suspected finding = injectable by timing only, seen under throttling.
        params = sorted({f.raw.get("param") for f in findings
                         if f.raw.get("time_based_only") and f.raw.get("rate_limited")
                         and f.raw.get("param")})
        if not params:
            return findings

        # Re-test just those parameter(s) with a delay to defeat the timing
        # noise, then reconcile the clean-timing verdict with the first pass.
        delay = os.environ.get(_DELAY_ENV) or _VERIFY_DELAY_DEFAULT
        argv = self._argv(target, intensity, delay=delay, only_params=",".join(params))
        verified = self.parse([runner.run(argv, timeout=_VERIFY_TIMEOUT)], target, intensity)
        return self._reconcile(findings, verified, target)

    def _reconcile(
        self, findings: list[Finding], verified: list[Finding], target: Target
    ) -> list[Finding]:
        suspects = [f for f in findings
                    if f.raw.get("time_based_only") and f.raw.get("rate_limited")]
        out = [f for f in findings if f not in suspects]

        # Anything the clean re-run confirms as real (HIGH+) stands on its own.
        real = [f for f in verified if f.severity >= Severity.HIGH]
        out += real
        confirmed = {f.raw.get("param") for f in real}
        still_suspect = {f.raw.get("param") for f in verified
                         if f.raw.get("time_based_only") and f.raw.get("rate_limited")}

        for p in sorted({s.raw.get("param") for s in suspects}):
            if p in confirmed:
                continue                                   # promoted to real above
            if p in still_suspect:
                # Even the delayed run was throttled — keep the suspicion, but
                # say the delay was not enough.
                orig = next(s for s in suspects if s.raw.get("param") == p)
                out.append(self._info(
                    orig.title + " [still unverified]",
                    f"{target.web_target} param '{p}': time-based only, and the "
                    f"delayed re-run was still rate-limited. Try a larger "
                    f"{_DELAY_ENV}.", target, severity=Severity.MEDIUM))
            else:
                out.append(self._info(
                    f"sqlmap: suspected SQL injection in '{p}' not confirmed",
                    f"{target.web_target} param '{p}' was flagged only by time-based "
                    f"payloads under rate-limiting; a delayed re-run found it not "
                    f"injectable — a throttling-induced false positive.", target))
        return out

    # -- parsing ----------------------------------------------------------
    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        res = results[0] if results else None
        out = (res.stdout if res else "") or ""
        low = out.lower()
        where = target.web_target

        if not out.strip():
            msg = (res.stderr.strip() if res else "") or "sqlmap produced no output"
            return [self._info("sqlmap produced no output", msg, target, out=out)]

        rate_limited = any(s in low for s in _RATE_LIMITED)

        # 1) Injectable parameters win over everything else.
        params = list(_PARAM_RE.finditer(out))
        if params:
            return self._vulnerabilities(out, params, target, intensity, rate_limited)

        reached = any(s in low for s in _REACHED_SIGNALS)
        fatal_unreach = _FATAL_UNREACH.search(out)

        # 2) Genuinely never reached the target: a critical connect failure and
        #    no sign we ever fetched a page. This is a *missing* test, not a
        #    clean result — keep it clearly distinct.
        if fatal_unreach and not reached:
            line = fatal_unreach.group(0).strip()
            return [self._info("sqlmap could not reach the target",
                               f"{where} — {line}", target, out=out)]

        # 3) Reached and tested, but nothing was injectable.
        if any(s in low for s in _NOT_VULN):
            return [self._info("sqlmap: no SQL injection found", where, target, out=out)]

        # 4) Reached, but there was nothing to test (no form/params/links).
        if any(s in low for s in _NO_TESTABLE):
            return [self._info("sqlmap: no testable parameters or forms",
                               where, target, out=out)]

        # 5) A connect failure after we had already reached the target: a
        #    crawled/secondary link was down. The target itself was tested.
        if fatal_unreach:
            return [self._info("sqlmap: no SQL injection found",
                               f"{where} (a crawled link was unreachable)", target, out=out)]

        # 6) Anything else: sqlmap ran but drew no clear conclusion we recognize.
        return [self._info("sqlmap: no injectable parameters tested", where, target, out=out)]

    def _vulnerabilities(
        self, out: str, params: list[re.Match], target: Target,
        intensity: Intensity, rate_limited: bool,
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
            # Confirmed by timing alone, while the target was throttling us?
            # Then this is the classic time-based false positive — report it as
            # a MEDIUM *suspicion*, not a HIGH confirmation.
            time_based_only = bool(titles) and all(_is_time_based(t) for t in titles)
            suspect = time_based_only and rate_limited

            if suspect:
                severity = Severity.MEDIUM
                title = (f"Suspected SQL injection in parameter '{name}' ({method}) "
                         f"— time-based only, unverified under rate-limiting")
                desc = (f"sqlmap flagged '{name}' as injectable against {dbms}, but ONLY via "
                        f"time-based payloads ({'; '.join(titles)}) while the target was "
                        f"rate-limiting. Response-time jitter from throttling is a common "
                        f"cause of false time-based detections, so this is not confirmed. "
                        f"Re-test with a delay (COSENTINEL_SQLMAP_DELAY) to decide.")
            else:
                severity = Severity.HIGH
                title = f"SQL injection in parameter '{name}' ({method})"
                desc = (f"Injectable against {dbms}. Techniques confirmed: "
                        + ("; ".join(titles) if titles else "see sqlmap output") + ".")

            findings.append(Finding(
                source=self.name, target=target.id, severity=severity,
                category=Category.VULNERABILITY,
                title=title,
                resource=f"{where} (param: {name} [{method}])",
                description=desc,
                remediation="Use parameterized queries / prepared statements; validate and "
                            "escape input; apply least-privilege to the DB account.",
                references=["CWE-89"],
                raw={"dbms": dbms, "method": method, "titles": titles, "param": name,
                     "time_based_only": time_based_only, "rate_limited": rate_limited,
                     "confidence": "low" if suspect else "high"},
            ))

        # EXPLOIT tier: a single CRITICAL proof-of-impact finding if sqlmap
        # actually reached the DBMS identity/data. (Data actually came back, so
        # this is real regardless of which technique carried it.)
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
    def _info(title: str, detail: str, target: Target, out: str = "",
              severity: Severity = Severity.INFO) -> Finding:
        # Keep a short stdout tail so an unexpected outcome can be diagnosed
        # without re-running the whole scan (the old INFO findings stored {}).
        tail = out.strip()[-800:] if out else ""
        return Finding(source="sqlmap", target=target.id, severity=severity,
                       category=Category.INFO if severity is Severity.INFO else Category.VULNERABILITY,
                       title=title, description=detail,
                       resource=target.web_target, raw={"stdout_tail": tail} if tail else {})
