"""Correlation & prioritization — the step that makes Cosentinel more than a
launcher of separate tools.

Each scanner reports in isolation. This module joins their findings for one
target into **risks**: a weak configuration (Lynis) on a port that is also open
to the network (Nmap) and carries a known CVE (Nuclei) is one serious risk, not
three unrelated lines — and it should outrank any of them alone.

The join key is the *asset*. Most network/web/TLS/vuln findings carry a port in
their `resource`; we extract it and group by it. Lynis `SSH-*` tests are mapped
to port 22 on purpose, so "SSH is weakly configured" lands on the same asset as
"port 22 is open" and the two reinforce each other.

The scoring is deliberately simple and explainable (every point has a reason in
`rationale`) rather than a black box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import Category, Finding, Severity

# Tools that *actively attack*: a HIGH+ finding from one of these is a weakness
# that was demonstrated, not merely signatured — the strongest possible signal.
_ACTIVE_SOURCES = {"sqlmap", "zap"}

_PORT_SLASH = re.compile(r"^(\d{1,5})/")        # nmap "22/tcp"
_PORT_COLON = re.compile(r":(\d{2,5})(?:/|$)")   # "host:443", "id:443", "http://h:8080/x"


def extract_port(f: Finding) -> int | None:
    """Best-effort port for a finding, or None if it isn't port-scoped."""
    r = f.resource or ""
    m = _PORT_SLASH.match(r)
    if m:
        return _valid(int(m.group(1)))
    m = _PORT_COLON.search(r)
    if m:
        return _valid(int(m.group(1)))
    # A web URL with no explicit port maps to its scheme's conventional port, so
    # that active web findings (sqlmap/zap/nuclei) land on the same asset as the
    # open 80/443 that nmap saw — and reinforce it.
    rl = r.lower()
    if rl.startswith("https://"):
        return 443
    if rl.startswith("http://"):
        return 80
    # Lynis SSH hardening tests belong to the SSH service.
    if f.source == "lynis" and r.upper().startswith("SSH"):
        return 22
    return None


def _valid(p: int) -> int | None:
    return p if 1 <= p <= 65535 else None


def asset_key(f: Finding) -> str:
    port = extract_port(f)
    if port is not None:
        return f"port {port}"
    if f.source == "lynis":
        return "host hardening"
    if f.category == Category.WEB:
        return "web service"
    return "other"


@dataclass
class Risk:
    key: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def sources(self) -> list[str]:
        """Every tool that touched this asset (including ones that only added
        informational context) — shown for transparency."""
        return sorted({f.source for f in self.findings})

    @property
    def corroborating_sources(self) -> list[str]:
        """Tools that found an *actual* problem here (severity >= LOW).

        A tool that reported only INFO — "port open", "no TLS issues", "no
        template matches", "could not reach" — did not corroborate anything, so
        it must not inflate the "corroborated by N tools" signal (and reachability
        is already credited separately via `exposed`)."""
        return sorted({f.source for f in self.findings if f.severity >= Severity.LOW})

    @property
    def exposed(self) -> bool:
        """Is this asset reachable — did a network scan see it open?"""
        return any(
            f.source == "nmap" and f.category == Category.NETWORK for f in self.findings
        )

    @property
    def has_cve(self) -> bool:
        return any(
            ref.upper().startswith("CVE-") for f in self.findings for ref in f.references
        )

    @property
    def actively_confirmed(self) -> bool:
        """Did an attacking tool actually demonstrate a HIGH+ weakness here?"""
        return any(
            f.source in _ACTIVE_SOURCES and f.severity >= Severity.HIGH
            for f in self.findings
        )

    @property
    def score(self) -> int:
        """Explainable priority score. Higher = more urgent."""
        s = int(self.severity) * 10          # the weakness itself dominates
        if len(self.corroborating_sources) >= 2:
            s += 5                            # multiple tools found a real problem
        if self.has_cve:
            s += 5                            # a public exploit path exists
        if self.exposed and self.severity >= Severity.MEDIUM:
            s += 8                            # reachable AND weak — the worst combo
        if self.actively_confirmed:
            s += 10                           # an attack actually worked here
        return s

    @property
    def rationale(self) -> str:
        bits: list[str] = []
        if self.actively_confirmed:
            bits.append("actively confirmed exploitable")
        if self.exposed and self.severity >= Severity.MEDIUM:
            bits.append("reachable from the network AND weak")
        elif self.exposed:
            bits.append("reachable from the network")
        corr = self.corroborating_sources
        if len(corr) >= 2:
            bits.append(f"corroborated by {len(corr)} tools ({', '.join(corr)})")
        if self.has_cve:
            bits.append("known CVE")
        return "; ".join(bits) or "single-source finding"

    def top(self) -> Finding | None:
        return max(self.findings, key=lambda f: int(f.severity), default=None)


def correlate(findings: list[Finding]) -> list[Risk]:
    """Group findings into risks, ranked most urgent first."""
    groups: dict[str, Risk] = {}
    for f in findings:
        key = asset_key(f)
        groups.setdefault(key, Risk(key=key)).findings.append(f)
    return sorted(
        groups.values(),
        key=lambda r: (r.score, int(r.severity), len(r.findings)),
        reverse=True,
    )
