"""Nmap adapter — network surface seen from *outside* the machine.

Runs from this laptop toward the target's host, the way an attacker on the same
network would see it. SAFE intensity does service/version detection only; the
adapter will not escalate past what the profile permits.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

# Services that carry credentials/data in clear text or are notoriously risky
# to expose. Seeing one open is itself a finding, regardless of version.
_PLAINTEXT_OR_RISKY = {
    "telnet": "Telnet transmits credentials in clear text.",
    "ftp": "FTP transmits credentials and data in clear text.",
    "rlogin": "rlogin is unauthenticated/clear-text legacy access.",
    "rsh": "rsh is unauthenticated/clear-text legacy access.",
    "vnc": "VNC is often unencrypted and a common intrusion vector.",
    "microsoft-ds": "SMB exposed to the network is a frequent attack surface.",
    "ms-wbt-server": "RDP exposed to the network is a frequent attack surface.",
}


@register
class NmapAdapter(Adapter):
    name = "nmap"
    requires_tool = "nmap"
    runs_on = "scanner"
    max_intensity = Intensity.AGGRESSIVE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        argv = ["nmap", "-sV", "-Pn", "-T3", "-oX", "-"]
        if intensity >= Intensity.AGGRESSIVE:
            # Default + vuln NSE scripts. Gated by the scope layer (--confirm).
            argv += ["-sC", "--script", "vuln"]
        argv.append(target.host)
        return [PlannedCommand(argv=argv, timeout=1200, label="nmap service scan")]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        res = results[0] if results else None
        if not res or not res.stdout.strip():
            msg = (res.stderr.strip() if res else "") or "nmap produced no output"
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="Nmap produced no output",
                description=msg,
            )]
        try:
            root = ET.fromstring(res.stdout)
        except ET.ParseError as e:
            return [Finding(
                source=self.name, target=target.id, severity=Severity.INFO,
                category=Category.INFO, title="Could not parse nmap output",
                description=str(e), raw={"stderr": res.stderr[:500]},
            )]

        findings: list[Finding] = []
        open_ports = 0
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            open_ports += 1
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = (svc.get("name") if svc is not None else "") or "unknown"
            product = (svc.get("product") if svc is not None else "") or ""
            version = (svc.get("version") if svc is not None else "") or ""
            banner = " ".join(p for p in (product, version) if p).strip()
            where = f"{portid}/{proto}"

            risky = _PLAINTEXT_OR_RISKY.get(name)
            if risky:
                findings.append(Finding(
                    source=self.name, target=target.id, severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                    title=f"Risky service exposed: {name} on {where}",
                    resource=where,
                    description=f"{risky} Detected as {banner or name}.",
                    remediation="Restrict this port (firewall/VPN) or replace with an "
                                "encrypted equivalent (e.g. SSH/SFTP instead of telnet/FTP).",
                    raw={"service": name, "banner": banner},
                ))
            else:
                findings.append(Finding(
                    source=self.name, target=target.id, severity=Severity.INFO,
                    category=Category.NETWORK,
                    title=f"Open port {where}: {name}" + (f" ({banner})" if banner else ""),
                    resource=where,
                    description="Open, reachable service observed from the scanner host.",
                    remediation="Confirm this port is meant to be reachable from where you "
                                "scanned; close or firewall it if not.",
                    raw={"service": name, "banner": banner},
                ))

        findings.append(Finding(
            source=self.name, target=target.id, severity=Severity.INFO,
            category=Category.INFO,
            title=f"Nmap: {open_ports} open port(s) on {target.host}",
            resource=target.host,
        ))
        return findings
