"""Nikto adapter — web-server findings, seen from outside.

Runs from this laptop toward the target's web endpoint. Nikto probes for common
misconfigurations, missing security headers, dangerous files and known-vulnerable
server versions. It writes JSON to a file, so (like testssl/lynis) we run it and
then read the file back.

Nikto does not assign severities, so we default each item to LOW and raise it to
MEDIUM when the message/id looks like a real vulnerability (a CVE, "vulnerable",
"outdated", a known injection/traversal class, …).
"""

from __future__ import annotations

import json
import re

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

_JSON = "/tmp/cosentinel-nikto.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
# Substrings that mark an item as more than cosmetic.
_BUMP = (
    "vulnerable", "outdated", "out of date", "traversal", "injection", "xss",
    "sql", "rce", "remote code", "deserial", "default account", "backdoor",
)


@register
class NiktoAdapter(Adapter):
    name = "nikto"
    requires_tool = "nikto"
    runs_on = "scanner"
    max_intensity = Intensity.SAFE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        return [
            PlannedCommand(
                argv=[
                    "nikto",
                    "-host", target.web_target,
                    "-Format", "json",
                    "-output", _JSON,
                    "-ask", "no",          # never prompt for updates
                    "-nointeractive",
                ],
                timeout=1800,
                label="nikto scan",
            ),
            PlannedCommand(argv=["cat", _JSON], timeout=60, label="read nikto json"),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        report = results[-1].stdout if results else ""
        try:
            data = json.loads(report) if report.strip() else []
        except json.JSONDecodeError:
            audit = results[0] if results else None
            msg = (audit.stderr.strip() if audit else "") or "nikto produced no JSON"
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="nikto produced no parseable output",
                description=msg,
            )]

        hosts = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            for vuln in host.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                findings.append(self._to_finding(vuln, target))

        if not findings:
            findings.append(Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="nikto: no web issues found",
                resource=target.web_target,
            ))
        return findings

    def _to_finding(self, vuln: dict, target: Target) -> Finding:
        msg = str(vuln.get("msg", "")).strip()
        vid = str(vuln.get("id", "")).strip()
        method = str(vuln.get("method", "GET")).strip()
        url = str(vuln.get("url", "")).strip()
        refs_field = str(vuln.get("references", "") or "")

        cves = sorted(set(_CVE_RE.findall(f"{msg} {vid} {refs_field}")))
        haystack = f"{msg} {vid}".lower()
        sev = Severity.MEDIUM if (cves or any(k in haystack for k in _BUMP)) else Severity.LOW

        return Finding(
            source=self.name, target=target.id, severity=sev, category=Category.WEB,
            title=msg or vid or "nikto finding",
            resource=f"{method} {url}".strip(),
            description="Reported by a Nikto web-server scan.",
            remediation="Review this on the web server (add the missing header, remove the "
                        "exposed file/path, or upgrade the affected component).",
            references=cves,
            raw={"id": vid},
        )
