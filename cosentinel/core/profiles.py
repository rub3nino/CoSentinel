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


# Built-in profiles. v1 ships detection only — the hardest built-in is SAFE.
# Aggressive/exploit profiles are intentionally *not* shipped; you compose them
# deliberately, and the scope layer gates them.
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
    "full": Profile(
        name="full",
        description="Everything in v1: hardening + network + known vulnerabilities.",
        intensity=Intensity.SAFE,
        adapters=("lynis", "nmap", "nuclei"),
    ),
}


def get_profile(name: str) -> Profile:
    try:
        return BUILTIN_PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(BUILTIN_PROFILES))
        raise KeyError(f"unknown profile {name!r}; known profiles: {known}") from None
