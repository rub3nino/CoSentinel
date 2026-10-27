"""The normalized Finding model.

Everything every scanner produces is funneled into one shape: a `Finding`.
Once that is true, the dashboard, the diff between two scans, trends and
prioritization all come almost for free. Adapters are the only code allowed to
construct raw findings; the rest of the system only ever reads them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so findings sort naturally (highest risk first)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        key = str(value).strip().upper()
        aliases = {
            "INFORMATIONAL": cls.INFO,
            "UNKNOWN": cls.INFO,
            "NONE": cls.INFO,
            "WARNING": cls.MEDIUM,
            "MODERATE": cls.MEDIUM,
        }
        if key in cls.__members__:
            return cls[key]
        return aliases.get(key, cls.INFO)

    @property
    def label(self) -> str:
        return self.name.capitalize()


# Broad buckets a finding can belong to. Kept as plain strings on purpose:
# adapters stay free to add their own, this is just the shared vocabulary.
class Category:
    HARDENING = "hardening"      # weak/insecure configuration (Lynis)
    NETWORK = "network"          # exposed ports / services (Nmap)
    VULNERABILITY = "vuln"       # a known vulnerability / CVE (Nuclei, OpenVAS)
    TLS = "tls"                  # certificate / TLS issues
    WEB = "web"                  # web-application issues
    INFO = "info"                # neutral context, not a problem by itself


@dataclass
class Finding:
    """One normalized observation about one target."""

    source: str                 # adapter that produced it, e.g. "lynis"
    target: str                 # target id this refers to
    severity: Severity
    category: str
    title: str
    resource: str = ""          # what it is about: a test id, port, URL, path
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)   # CVEs, URLs, test ids
    raw: dict = field(default_factory=dict)               # evidence, redacted
    # Filled in by the store, not by adapters:
    first_seen: str | None = None
    last_seen: str | None = None

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)

    @property
    def fingerprint(self) -> str:
        """Stable identity across scans.

        The same underlying problem must hash to the same fingerprint on every
        run, otherwise the diff ("what changed since yesterday") is meaningless.
        So it deliberately excludes timestamps and volatile evidence.
        """
        basis = "\x1f".join(
            [self.source, self.target, self.category, self.resource, self.title]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        d["fingerprint"] = self.fingerprint
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
