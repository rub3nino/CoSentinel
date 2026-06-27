import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from models import Finding, Severity

EXTRA_PATTERNS = {
    "OpenAI Key": r"sk-[a-zA-Z0-9]{20,}",
    "Anthropic Key": r"sk-ant-[a-zA-Z0-9\-_]{20,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Config": r"firebase.*apiKey.*:.*['\"][A-Za-z0-9\-_]{20,}['\"]",
    "Heroku API Key": r"[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Twilio Key": r"SK[0-9a-fA-F]{32}",
    "Azure Conn String": r"DefaultEndpointsProtocol=https;AccountName=",
    "DB Conn String": r"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]{4,}@",
    "NPM Token": r"npm_[a-zA-Z0-9]{36}",
    "Vault Token": r"hvs\.[a-zA-Z0-9]{24,}",
}


def _severity(pattern_name: str, rel_path: str) -> Severity:
    if rel_path.endswith((".env.example", ".env.sample")):
        return Severity.LOW
    if "Private Key" in pattern_name or "AWS Secret" in pattern_name or pattern_name in {
        "OpenAI Key",
        "Anthropic Key",
        "Google API Key",
    }:
        return Severity.CRITICAL
    return Severity.HIGH


def _scan_file(local_path: str, rel_path: str, compiled: dict[str, re.Pattern[str]]) -> list[tuple[int, str, str, Severity]]:
    if rel_path.endswith((".md", ".txt", ".rst")):
        return []
    abs_path = os.path.join(local_path, rel_path)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return []

    matches = []
    for line_number, line in enumerate(lines, 1):
        for pattern_name, pattern in compiled.items():
            for match in pattern.finditer(line):
                evidence = match.group(0)[:6] + "***REDACTED***"
                matches.append((line_number, pattern_name, evidence, _severity(pattern_name, rel_path)))
    return matches


def scan_secrets(local_path: str, all_files: list[str]) -> list[Finding]:
    compiled = {
        name: re.compile(regex)
        for name, regex in {**config.SECRET_PATTERNS, **EXTRA_PATTERNS}.items()
    }
    findings: list[Finding] = []
    counter = 1

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_scan_file, local_path, rel_path, compiled): rel_path
            for rel_path in all_files
        }
        results = []
        for future in as_completed(futures):
            results.extend((futures[future], *item) for item in future.result())

    results.sort(key=lambda item: (item[0], item[1], item[2]))
    for rel_path, line_number, pattern_name, evidence, severity in results:
        findings.append(
            Finding(
                id=f"SEC-{counter:03d}",
                severity=severity,
                category="secret",
                title=f"{pattern_name} detected",
                description="Hardcoded credential found in source code. If this is a real credential, it must be rotated immediately.",
                file_path=rel_path,
                line_number=line_number,
                evidence=evidence,
                fix_suggestion="Remove from code. Add file to .gitignore. Rotate the credential. Use environment variables instead.",
                auto_fixable=False,
            )
        )
        counter += 1
    return findings
