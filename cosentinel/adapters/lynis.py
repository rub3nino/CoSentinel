"""Lynis adapter — host hardening audit, seen from *inside* the machine.

Lynis is run on the target (over SSH, or locally) because it has to read the
machine's own configuration. It writes a machine-readable report file; we read
that file back and turn each warning/suggestion into a finding, plus one INFO
finding carrying the overall hardening index.
"""

from __future__ import annotations

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

_REPORT = "/tmp/cosentinel-lynis-report.dat"


@register
class LynisAdapter(Adapter):
    name = "lynis"
    requires_tool = "lynis"
    runs_on = "target"
    max_intensity = Intensity.SAFE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        sudo = target.sudo
        return [
            PlannedCommand(
                argv=[
                    "lynis", "audit", "system",
                    "--quiet", "--no-colors",
                    "--report-file", _REPORT,
                ],
                sudo=sudo,
                timeout=900,
                label="lynis audit system",
            ),
            PlannedCommand(
                argv=["cat", _REPORT],
                sudo=sudo,
                timeout=60,
                label="read lynis report",
            ),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        report = results[-1].stdout if results else ""
        if not report.strip():
            audit = results[0] if results else None
            detail = (audit.stderr.strip() if audit else "") or "no lynis report produced"
            return [
                Finding(
                    source=self.name, target=target.id, severity=Severity.INFO,
                    category=Category.INFO, title="Lynis produced no report",
                    description=detail,
                    remediation="Ensure lynis is installed and sudo is available on the target.",
                )
            ]

        findings: list[Finding] = []
        for key, value in _iter_report(report):
            if key == "warning[]":
                test_id, text = _split_entry(value)
                findings.append(Finding(
                    source=self.name, target=target.id, severity=Severity.MEDIUM,
                    category=Category.HARDENING, title=text or test_id,
                    resource=test_id,
                    description="Lynis flagged this as a warning (a weak or risky setting).",
                    remediation=f"See Lynis test {test_id}: run `lynis show details {test_id}`.",
                    references=[test_id] if test_id else [],
                ))
            elif key == "suggestion[]":
                test_id, text = _split_entry(value)
                findings.append(Finding(
                    source=self.name, target=target.id, severity=Severity.LOW,
                    category=Category.HARDENING, title=text or test_id,
                    resource=test_id,
                    description="Lynis suggests a hardening improvement here.",
                    remediation=f"See Lynis test {test_id}: run `lynis show details {test_id}`.",
                    references=[test_id] if test_id else [],
                ))
            elif key == "hardening_index":
                findings.append(Finding(
                    source=self.name, target=target.id, severity=Severity.INFO,
                    category=Category.INFO,
                    title=f"Lynis hardening index: {value}/100",
                    resource="hardening_index",
                    description="Overall hardening score reported by Lynis (higher is better).",
                    raw={"hardening_index": value},
                ))
        return findings


def _iter_report(report: str):
    for line in report.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        yield key.strip(), value.strip()


def _split_entry(value: str) -> tuple[str, str]:
    """Lynis warning/suggestion values look like: TEST-ID|human text|...|...."""
    parts = value.split("|")
    test_id = parts[0].strip() if parts else ""
    text = parts[1].strip() if len(parts) > 1 else ""
    return test_id, text
