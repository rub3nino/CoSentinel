"""Scan intensity and named profiles.

The single most important safety idea in Cosentinel: *finding* a weakness and
*exploiting* it are not the same act and must not sit behind the same button.
Intensity is the manopola that separates them. Every adapter is handed an
intensity and decides how far it is allowed to go; the scope layer refuses the
dangerous ones unless you explicitly opt in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Intensity(IntEnum):
    """How invasive a scan is allowed to be. Ordered, low to high."""

    PASSIVE = 0      # observe only, never touch the target (lookups, banners)
    SAFE = 1         # probe without forcing anything (default for all v1 tools)
    AGGRESSIVE = 2   # may disturb a service (fuzzing, brute-force, heavy scripts)
    EXPLOIT = 3      # actually exploit to prove impact — can break things

    @classmethod
    def parse(cls, value: "str | int | Intensity") -> "Intensity":
        if isinstance(value, Intensity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(3, value)))
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()


# Anything at or above this needs an explicit --confirm on the command line.
CONFIRM_FROM = Intensity.AGGRESSIVE
# Anything at or above this additionally requires the target to be marked `lab`.
LAB_ONLY_FROM = Intensity.EXPLOIT


@dataclass(frozen=True)
class Profile:
    """A named bundle: which adapters to run, and how hard."""

    name: str
    description: str
    intensity: Intensity
    adapters: tuple[str, ...]


# Built-in profiles. The detection profiles are SAFE and run with no extra
# ceremony. The active-testing profiles (`pentest`, `exploit`) send real
# payloads the way a human tester would; they are gated by the scope layer —
# `pentest` needs an explicit --confirm, `exploit` additionally needs the
# target marked `lab: true`. Each adapter still clamps itself to its own
# ceiling, so a profile's intensity is the *most* any tool is allowed to do.
BUILTIN_PROFILES: dict[str, Profile] = {
    "audit": Profile(
        name="audit",
        description="Host hardening audit from the inside (Lynis over SSH).",
        intensity=Intensity.SAFE,
        adapters=("lynis",),
    ),
    "network": Profile(
        name="network",
        description="Network surface seen from outside (Nmap service/version).",
        intensity=Intensity.SAFE,
        adapters=("nmap",),
    ),
    "vuln": Profile(
        name="vuln",
        description="Known-vulnerability detection against exposed services (Nuclei).",
        intensity=Intensity.SAFE,
        adapters=("nuclei",),
    ),
    "tls": Profile(
        name="tls",
        description="TLS/certificate posture of an exposed service (testssl.sh).",
        intensity=Intensity.SAFE,
        adapters=("testssl",),
    ),
    "web": Profile(
        name="web",
        description="Web-server misconfigurations and dangerous files (Nikto).",
        intensity=Intensity.SAFE,
        adapters=("nikto",),
    ),
    "full": Profile(
        name="full",
        description="Everything: hardening + network + known vulns + TLS + web.",
        intensity=Intensity.SAFE,
        adapters=("lynis", "nmap", "nuclei", "testssl", "nikto"),
    ),
    "openvas": Profile(
        name="openvas",
        description="Deep vulnerability scan via a running Greenbone/GVM instance (gvm-cli).",
        intensity=Intensity.SAFE,
        adapters=("openvas",),
    ),
    # -- active testing (gated) -------------------------------------------
    "pentest": Profile(
        name="pentest",
        description="Active testing like a human attacker: aggressive Nmap + "
                    "heavy web probing. Needs --confirm.",
        intensity=Intensity.AGGRESSIVE,
        adapters=("lynis", "nmap", "nuclei", "testssl", "nikto"),
    ),
    "exploit": Profile(
        name="exploit",
        description="Prove impact, not just presence. Each tool goes as far as it "
                    "can. Needs --confirm AND a target marked lab:true.",
        intensity=Intensity.EXPLOIT,
        adapters=("nmap", "nuclei", "testssl", "nikto"),
    ),
}


def get_profile(name: str) -> Profile:
    try:
        return BUILTIN_PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(BUILTIN_PROFILES))
        raise KeyError(f"unknown profile {name!r}; known profiles: {known}") from None
