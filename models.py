from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str                        # unique: "DEP-001", "SEC-003", etc.
    severity: Severity
    category: str                  # "dependency", "secret", "code", "config"
    title: str
    description: str
    file_path: Optional[str]       # relative path in repo
    line_number: Optional[int]
    evidence: str                  # exact snippet or CVE id
    cve_ids: list[str] = field(default_factory=list)
    fix_suggestion: str = ""       # human-readable fix
    auto_fixable: bool = False     # can PR creator auto-fix this?
    fix_patch: Optional[str] = None  # unified diff string if auto_fixable


@dataclass
class ScanResult:
    repo_url: str
    repo_name: str
    local_path: str
    findings: list[Finding] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def critical_count(self) -> int:
        return len(self.by_severity(Severity.CRITICAL))

    def high_count(self) -> int:
        return len(self.by_severity(Severity.HIGH))
