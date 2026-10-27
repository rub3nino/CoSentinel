"""Nuclei adapter — known-vulnerability detection against exposed services.

Nuclei runs from this laptop toward the target's URL/host and matches a large,
community-maintained template set (CVEs, misconfigurations, exposures). We do
not reimplement its detections — we normalize its JSONL output into findings.
"""

from __future__ import annotations

import json

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register


@register
class NucleiAdapter(Adapter):
    name = "nuclei"
    requires_tool = "nuclei"
    runs_on = "scanner"
    max_intensity = Intensity.SAFE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        argv = [
            "nuclei",
            "-target", target.web_target,
            "-jsonl",          # one JSON object per line
            "-silent",         # no banner / progress on stdout
            "-nc",             # no color
            "-severity", "info,low,medium,high,critical",
        ]
        return [PlannedCommand(argv=argv, timeout=1800, label="nuclei scan")]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        res = results[0] if results else None
        if res is None:
            return []
        findings: list[Finding] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._to_finding(obj, target))

        if not findings:
            findings.append(Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO,
                title="Nuclei: no template matches",
                resource=target.web_target,
                description="No known-vulnerability templates matched this target.",
            ))
        return findings

    def _to_finding(self, obj: dict, target: Target) -> Finding:
        info = obj.get("info", {}) or {}
        sev = Severity.parse(info.get("severity", "info"))
        tags = info.get("tags") or []
        category = Category.TLS if "ssl" in tags or "tls" in tags else Category.VULNERABILITY

        refs: list[str] = []
        classification = info.get("classification") or {}
        for cve in classification.get("cve-id") or []:
            refs.append(cve)
        reference = info.get("reference")
        if isinstance(reference, list):
            refs.extend(reference)
        elif isinstance(reference, str):
            refs.append(reference)

        return Finding(
            source=self.name, target=target.id, severity=sev, category=category,
            title=info.get("name") or obj.get("template-id", "nuclei match"),
            resource=obj.get("matched-at") or obj.get("host") or target.web_target,
            description=info.get("description", "") or "",
            remediation=info.get("remediation", "") or
                        "Patch/upgrade the affected component or restrict access to it.",
            references=[r for r in refs if r],
            raw={"template-id": obj.get("template-id"), "type": obj.get("type")},
        )
