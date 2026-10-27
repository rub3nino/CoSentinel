"""The engine — the director of the orchestra.

Given a set of targets and a profile, it: authorizes each target through the
scope layer, picks the right runner per adapter (inside the box vs. from
outside), runs the adapters that are available, normalizes everything into
findings, and persists a scan. It never touches a machine directly — that is
the transport layer's job — and it never decides what is allowed — that is the
scope layer's job. It only coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..adapters.base import Adapter, PlannedCommand, get_adapter
from ..transport.ssh import LocalRunner, Runner, SSHRunner
from .findings import Category, Finding, Severity
from .profiles import Intensity, Profile
from .scope import Scope, Target
from .store import Store

Logger = Callable[[str], None]


@dataclass
class AdapterRun:
    adapter: str
    runner: str
    planned: list[PlannedCommand] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: str | None = None


@dataclass
class TargetScan:
    target: str
    profile: str
    intensity: Intensity
    scan_id: int | None = None
    runs: list[AdapterRun] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.runs:
            out.extend(r.findings)
        return out


class Engine:
    def __init__(self, scope: Scope, store: Store, log: Logger | None = None):
        self.scope = scope
        self.store = store
        self.log = log or (lambda _msg: None)

    def run(
        self,
        target_ids: list[str],
        profile: Profile,
        *,
        confirmed: bool = False,
        dry_run: bool = False,
    ) -> list[TargetScan]:
        return [
            self._scan_target(tid, profile, confirmed=confirmed, dry_run=dry_run)
            for tid in target_ids
        ]

    def _scan_target(
        self, target_id: str, profile: Profile, *, confirmed: bool, dry_run: bool
    ) -> TargetScan:
        # 1) The gate. Raises if the target is out of scope or under-authorized.
        target = self.scope.authorize(target_id, profile.intensity, confirmed=confirmed)
        ts = TargetScan(target=target_id, profile=profile.name, intensity=profile.intensity)

        # 2) Two runners: one "inside" the target, one "outside" toward it.
        target_runner = self._target_runner(target)
        scanner_runner: Runner = LocalRunner()

        scan_id = None
        if not dry_run:
            scan_id = self.store.start_scan(
                target_id, profile.name, profile.intensity.label
            )
            ts.scan_id = scan_id

        status = "done"
        try:
            for name in profile.adapters:
                adapter = get_adapter(name)
                runner = target_runner if adapter.runs_on == "target" else scanner_runner
                run = AdapterRun(adapter=name, runner=runner.describe())

                if not adapter.supports(profile.intensity):
                    run.skipped = f"adapter caps at {adapter.max_intensity.label}"
                    ts.runs.append(run)
                    continue

                if dry_run:
                    run.planned = adapter.plan(target, profile.intensity)
                    ts.runs.append(run)
                    continue

                if not adapter.available(runner):
                    self.log(f"  [{name}] {adapter.requires_tool} not found on {runner.describe()} — skipped")
                    run.skipped = f"{adapter.requires_tool} not installed on {runner.describe()}"
                    run.findings = [Finding(
                        source=name, target=target_id, severity=Severity.INFO,
                        category=Category.INFO,
                        title=f"{adapter.requires_tool} not installed on {runner.describe()}",
                        remediation=f"Install {adapter.requires_tool} to enable the {name} adapter.",
                    )]
                    for f in run.findings:
                        self.store.add_finding(scan_id, f)
                    ts.runs.append(run)
                    continue

                self.log(f"  [{name}] running on {runner.describe()} …")
                run.findings = adapter.scan(runner, target, profile.intensity)
                for f in run.findings:
                    self.store.add_finding(scan_id, f)
                self.log(f"  [{name}] {len(run.findings)} finding(s)")
                ts.runs.append(run)
        except Exception:
            status = "error"
            raise
        finally:
            if not dry_run and scan_id is not None:
                self.store.finish_scan(scan_id, status)

        return ts

    @staticmethod
    def _target_runner(target: Target) -> Runner:
        if target.is_local:
            return LocalRunner()
        return SSHRunner(target.host, user=target.user, port=target.port)
