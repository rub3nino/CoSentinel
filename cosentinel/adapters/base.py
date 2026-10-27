"""The adapter contract — the seam where Cosentinel grows.

Every scanner is an Adapter implementing the same tiny interface. Adding a new
tool (OpenVAS, testssl, ZAP, …) means writing one file here and registering it;
nothing else in the codebase has to change. That is the whole point of the
plugin design.

An adapter declares *where* it runs:
  * runs_on = "target"  -> inside the machine (Lynis reads its config). The
    engine hands it a runner connected to the target (SSH, or local).
  * runs_on = "scanner" -> from this laptop *toward* the target (Nmap, Nuclei
    look at it from outside). The engine hands it the local runner.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..core.findings import Finding
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult, Runner


@dataclass
class PlannedCommand:
    """One command the adapter intends to run. Surfaced by --dry-run so you can
    always see exactly what will execute before it does."""

    argv: list[str]
    sudo: bool = False
    timeout: int = 600
    label: str = ""


class Adapter(ABC):
    name: str = ""
    requires_tool: str = ""
    runs_on: str = "target"            # "target" | "scanner"
    max_intensity: Intensity = Intensity.SAFE

    # -- capability checks ------------------------------------------------
    def supports(self, intensity: Intensity) -> bool:
        return intensity <= self.max_intensity

    def available(self, runner: Runner) -> bool:
        return runner.which(self.requires_tool)

    # -- the two things every adapter must implement ----------------------
    @abstractmethod
    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        """Return the command(s) to run, in order."""

    @abstractmethod
    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        """Turn raw command output into normalized findings."""

    # -- default orchestration (adapters rarely override this) ------------
    def scan(self, runner: Runner, target: Target, intensity: Intensity) -> list[Finding]:
        results: list[CommandResult] = []
        for pc in self.plan(target, intensity):
            results.append(runner.run(pc.argv, timeout=pc.timeout, sudo=pc.sudo))
        return self.parse(results, target, intensity)


# -- registry -------------------------------------------------------------
_REGISTRY: dict[str, Adapter] = {}


def register(cls: type[Adapter]) -> type[Adapter]:
    inst = cls()
    if not inst.name:
        raise ValueError(f"{cls.__name__} has no name")
    if inst.name in _REGISTRY:
        raise ValueError(f"duplicate adapter name {inst.name!r}")
    _REGISTRY[inst.name] = inst
    return cls


def get_adapter(name: str) -> Adapter:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"unknown adapter {name!r}; registered: {known}") from None


def all_adapters() -> list[Adapter]:
    return list(_REGISTRY.values())
