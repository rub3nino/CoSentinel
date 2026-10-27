"""Scope and authorization — the layer that keeps the tool honest.

A tool that runs privileged scans over SSH is only trustworthy if it physically
cannot touch something you did not put on a list. So:

  * You can only scan a target that exists in the allowlist.
  * Anything AGGRESSIVE or above requires an explicit confirmation.
  * Anything EXPLOIT-level additionally requires the target to be marked `lab`.
  * Every authorized action is written to an append-only audit log, so there is
    always a record of what ran, where, and when.

This is not bureaucracy; it is what separates an audit tool from a footgun.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .findings import now_iso
from .profiles import CONFIRM_FROM, LAB_ONLY_FROM, Intensity


class AuthorizationError(Exception):
    """Raised when an action is not permitted. Never caught silently."""


@dataclass
class Target:
    """A machine Cosentinel is allowed to look at."""

    id: str
    host: str                       # ssh alias (from ~/.ssh/config), IP, hostname or domain
    ssh: bool = True                # True => reach it over SSH; False => local or web-only
    sudo: bool = False              # may we use sudo on the target (for Lynis)
    user: str | None = None         # optional ssh user override
    port: int | None = None         # optional ssh port override
    url: str | None = None          # optional base URL for web/vuln scanners
    tags: list[str] = field(default_factory=list)
    lab: bool = False               # explicitly a throwaway/lab box
    notes: str = ""

    @property
    def is_local(self) -> bool:
        """This very machine (no network hop)."""
        return self.host in ("localhost", "127.0.0.1", "::1")

    @property
    def can_scan_inside(self) -> bool:
        """Can we execute commands *inside* this target (for host-audit adapters
        like Lynis)? Only when it's the local box or reachable over SSH. A plain
        website/URL target (ssh:false, remote host) is web-only: outside-in
        scanners run against it, inside-the-host audits are skipped."""
        return self.is_local or self.ssh

    @property
    def web_target(self) -> str:
        """Best-effort URL/host for outside-in (web/vuln/TLS) scanners."""
        if self.url:
            return self.url
        return self.host


class AuditLog:
    """Append-only JSONL record of every authorized (or refused) action."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, action: str, *, target: str = "", detail: dict | None = None) -> None:
        entry = {
            "ts": now_iso(),
            "action": action,
            "target": target,
            "detail": detail or {},
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


class Scope:
    """The allowlist plus the authorization rules over it."""

    def __init__(self, targets: list[Target], audit: AuditLog | None = None):
        self._targets = {t.id: t for t in targets}
        if len(self._targets) != len(targets):
            raise ValueError("duplicate target id in scope")
        self.audit = audit

    # -- lookup -----------------------------------------------------------
    def __contains__(self, target_id: str) -> bool:
        return target_id in self._targets

    def get(self, target_id: str) -> Target:
        try:
            return self._targets[target_id]
        except KeyError:
            known = ", ".join(sorted(self._targets)) or "(none)"
            raise AuthorizationError(
                f"{target_id!r} is not in scope. Allowed targets: {known}"
            ) from None

    def all(self) -> list[Target]:
        return list(self._targets.values())

    # -- the gate ---------------------------------------------------------
    def authorize(
        self,
        target_id: str,
        intensity: Intensity,
        *,
        confirmed: bool = False,
    ) -> Target:
        """Return the target if the action is allowed, else raise.

        This is the only path through which a scan is permitted to start.
        """
        target = self.get(target_id)  # raises if not in allowlist

        if intensity >= CONFIRM_FROM and not confirmed:
            self._refuse(target_id, intensity, "needs explicit --confirm")
            raise AuthorizationError(
                f"{intensity.label} scans are disruptive and require explicit "
                f"confirmation (pass --confirm)."
            )

        if intensity >= LAB_ONLY_FROM and not target.lab:
            self._refuse(target_id, intensity, "target not marked lab")
            raise AuthorizationError(
                f"{intensity.label} scans only run against targets explicitly "
                f"marked `lab: true`. {target_id!r} is not."
            )

        if self.audit:
            self.audit.record(
                "authorize",
                target=target_id,
                detail={"intensity": intensity.label, "confirmed": confirmed},
            )
        return target

    def _refuse(self, target_id: str, intensity: Intensity, reason: str) -> None:
        if self.audit:
            self.audit.record(
                "refuse",
                target=target_id,
                detail={"intensity": intensity.label, "reason": reason},
            )
