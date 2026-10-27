"""Configuration: targets + settings, loaded from a YAML file you own.

The config *is* the allowlist. A machine that is not written here cannot be
scanned — that is intentional. Everything lives in the project under
`.cosentinel/` by default, so the whole state is one folder you control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .core.scope import AuditLog, Scope, Target

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # surfaced with a clear message in load()

# Where we look for a config, in order.
_SEARCH = [
    "cosentinel.yaml",
    "cosentinel.yml",
    ".cosentinel/config.yaml",
    os.path.expanduser("~/.config/cosentinel/config.yaml"),
]

SAMPLE = """\
# Cosentinel configuration — this file IS your allowlist.
# A machine not listed here cannot be scanned.

settings:
  db: .cosentinel/cosentinel.db
  audit_log: .cosentinel/audit.jsonl

targets:
  # The machine you are on right now (no SSH). Good for a first run.
  - id: localhost
    host: 127.0.0.1
    ssh: false
    sudo: true         # Lynis wants root to read system config
    lab: true          # a box you own outright

  # A remote home server reached over SSH. `host` matches an entry in your
  # ~/.ssh/config, or is an IP/hostname. Keys & agent are reused automatically.
  # - id: homeserver
  #   host: homeserver
  #   ssh: true
  #   sudo: true
  #   url: http://homeserver        # optional, for web/vuln scanners
  #   tags: [prod]
  #   lab: false

  # A website / web address you own or are authorized to test. ssh:false and a
  # non-local host make it "web-only": only outside-in scanners run (nmap,
  # nuclei, testssl, nikto); host-internal audits (Lynis) are skipped.
  # Only add sites you own or have explicit permission to scan.
  # - id: mysite
  #   host: example.com
  #   ssh: false
  #   url: https://example.com
  #   tags: [web]
  #   lab: false
"""


@dataclass
class Config:
    db_path: str
    audit_path: str
    targets: list[Target] = field(default_factory=list)
    source: str | None = None

    def scope(self) -> Scope:
        return Scope(self.targets, audit=AuditLog(self.audit_path))


def _target_from_dict(d: dict) -> Target:
    if "id" not in d or "host" not in d:
        raise ValueError(f"target needs at least 'id' and 'host': {d!r}")
    return Target(
        id=str(d["id"]),
        host=str(d["host"]),
        ssh=bool(d.get("ssh", True)),
        sudo=bool(d.get("sudo", False)),
        user=d.get("user"),
        port=d.get("port"),
        url=d.get("url"),
        tags=list(d.get("tags", []) or []),
        lab=bool(d.get("lab", False)),
        notes=str(d.get("notes", "")),
    )


def find_config(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    for cand in _SEARCH:
        p = Path(cand)
        if p.exists():
            return p
    return None


def load(path: str | None = None) -> Config:
    if yaml is None:
        raise RuntimeError(
            "PyYAML is required to read the config. Install it: pip install pyyaml"
        )
    found = find_config(path)
    if found is None:
        raise FileNotFoundError(
            "No config found. Run `cosentinel init` to create one."
        )
    data = yaml.safe_load(found.read_text(encoding="utf-8")) or {}
    settings = data.get("settings", {}) or {}
    targets = [_target_from_dict(t) for t in (data.get("targets") or [])]
    return Config(
        db_path=settings.get("db", ".cosentinel/cosentinel.db"),
        audit_path=settings.get("audit_log", ".cosentinel/audit.jsonl"),
        targets=targets,
        source=str(found),
    )


def init_project(directory: str = ".") -> Path:
    """Create a starter config and the state dir. Never overwrites."""
    root = Path(directory)
    (root / ".cosentinel").mkdir(parents=True, exist_ok=True)
    cfg = root / "cosentinel.yaml"
    if not cfg.exists():
        cfg.write_text(SAMPLE, encoding="utf-8")
    gi = root / ".cosentinel" / ".gitignore"
    if not gi.exists():
        # The local DB and audit log are yours; keep them out of git by default.
        gi.write_text("*.db\n*.jsonl\n", encoding="utf-8")
    return cfg
