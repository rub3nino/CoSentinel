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
        return [
            PlannedCommand(
                argv=[
                    "testssl.sh",
                    "--quiet",            # no banner
                    "--color", "0",       # no ANSI
                    "--warnings", "batch",  # never prompt
                    "--fast",             # skip exhaustive cipher enumeration
                    "--jsonfile", _JSON,
                    target.web_target,
                ],
                timeout=1800,
                label="testssl scan",
            ),
            PlannedCommand(argv=["cat", _JSON], timeout=60, label="read testssl json"),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        report = results[-1].stdout if results else ""
        try:
            entries = json.loads(report) if report.strip() else []
        except json.JSONDecodeError:
            audit = results[0] if results else None
            msg = (audit.stderr.strip() if audit else "") or "testssl produced no JSON"
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="testssl produced no parseable output",
                description=msg,
            )]

        findings: list[Finding] = []
        for obj in entries:
            if not isinstance(obj, dict):
                continue
            sev = _SEV_MAP.get(str(obj.get("severity", "")).upper(), None)
            if sev is None:
                continue  # healthy / non-actionable line
            test_id = str(obj.get("id", "")).strip()
            finding_text = str(obj.get("finding", "")).strip()
            port = str(obj.get("port", "")).strip()
            refs = [c for c in str(obj.get("cve", "")).split() if c.startswith("CVE")]
            findings.append(Finding(
                source=self.name, target=target.id, severity=sev, category=Category.TLS,
                title=finding_text or test_id,
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
