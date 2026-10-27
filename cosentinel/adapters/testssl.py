"""testssl.sh adapter — TLS / certificate posture, seen from outside.

Runs from this laptop toward the target's TLS endpoint and normalizes
testssl.sh's flat JSON output. testssl writes JSON to a file rather than
stdout, so we point it at a temp file and read it back (two planned commands,
like the Lynis adapter).

Only real problems are turned into findings: testssl emits an "OK"/"INFO" line
for every check it runs (e.g. "SSLv2: not offered"), which is healthy and would
otherwise flood the report, so those are skipped.
"""

from __future__ import annotations

import json

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

_JSON = "/tmp/cosentinel-testssl.json"


def _humanize(test_id: str) -> str:
    """'overall_grade' -> 'Overall grade' — a readable label from a testssl id."""
    return test_id.replace("_", " ").replace("-", " ").strip().capitalize()

# testssl meta entries that describe the scan or the local tool, not the target.
# `engine_problem` in particular is about the scanner host's openssl, so it must
# never become a finding about the target.
_SKIP_IDS = {"engine_problem", "scanProblem", "scanTime", "service", "pre_128cipher"}

# testssl severities -> our Severity. Values that mean "no problem" map to None
# and are dropped so the report only carries actionable findings.
_SEV_MAP = {
    "OK": None,
    "INFO": None,
    "DEBUG": None,
    "FATAL": None,       # scan/transport error, not a target weakness
    "WARN": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


@register
class TestsslAdapter(Adapter):
    name = "testssl"
    requires_tool = "testssl.sh"
    runs_on = "scanner"
    max_intensity = Intensity.SAFE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        # testssl refuses to overwrite an existing --jsonfile, so a stale file
        # from a previous run would make every later scan silently empty. Remove
        # it first. (--fast is intentionally dropped: testssl itself warns it is
        # no longer recommended.)
        return [
            PlannedCommand(argv=["rm", "-f", _JSON], timeout=30, label="clear stale testssl json"),
            PlannedCommand(
                argv=[
                    "testssl.sh",
                    "--quiet",            # no banner
                    "--color", "0",       # no ANSI
                    "--warnings", "batch",  # never prompt
                    "--jsonfile", _JSON,
                    target.web_target,
                ],
                timeout=2400,
                label="testssl scan",
            ),
            PlannedCommand(argv=["cat", _JSON], timeout=60, label="read testssl json"),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        cat = results[-1] if results else None
        scan = results[-2] if len(results) >= 2 else None
        report = cat.stdout if cat else ""

        if not report.strip():
            # Empty report: either testssl failed (surface its error) or the
            # target genuinely had nothing to report. Don't conflate the two.
            err = (scan.stderr.strip() if scan else "") or (cat.stderr.strip() if cat else "")
            if err:
                return [Finding(
                    source=self.name, target=target.id, severity=Severity.INFO,
                    category=Category.INFO, title="testssl did not produce a report",
                    description=err[:300],
                )]
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="testssl: no TLS issues found",
                resource=target.web_target,
            )]

        try:
            entries = json.loads(report)
        except json.JSONDecodeError:
            msg = (scan.stderr.strip() if scan else "") or "testssl output was not valid JSON"
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="testssl produced unparseable output",
                description=msg[:300],
            )]

        findings: list[Finding] = []
        for obj in entries:
            if not isinstance(obj, dict):
                continue
            if str(obj.get("id", "")) in _SKIP_IDS:
                continue  # scan/tool meta, not a target issue
            sev = _SEV_MAP.get(str(obj.get("severity", "")).upper(), None)
            if sev is None:
                continue  # healthy / non-actionable line
            test_id = str(obj.get("id", "")).strip()
            finding_text = str(obj.get("finding", "")).strip()
            port = str(obj.get("port", "")).strip()
            refs = [c for c in str(obj.get("cve", "")).split() if c.startswith("CVE")]
            # Some checks report a terse value (a grade like "T"/"A+"): on its own
            # that is an unreadable title, so prefix the humanized check id.
            label = _humanize(test_id)
            if len(finding_text) >= 5:
                title = finding_text
            elif finding_text:
                title = f"{label}: {finding_text}" if label else finding_text
            else:
                title = label or "TLS finding"
            findings.append(Finding(
                source=self.name, target=target.id, severity=sev, category=Category.TLS,
                title=title,
                resource=f"{test_id}:{port}" if port else test_id,
                description=f"testssl.sh check `{test_id}`.",
                remediation="Review the TLS/certificate configuration of this service "
                            "(disable weak protocols/ciphers, fix/renew the certificate).",
                references=refs,
                raw={"id": test_id, "severity": obj.get("severity")},
            ))

        if not findings:
            findings.append(Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="testssl: no TLS issues found",
                resource=target.web_target,
            ))
        return findings
