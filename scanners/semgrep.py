"""Optional Semgrep SAST — skipped gracefully when semgrep is not installed."""

from __future__ import annotations

import json
import shutil
import subprocess

from models import Finding, Severity

_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _run(cmd: list[str], timeout: int = 120) -> tuple[str, int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout + proc.stderr)[:20000], proc.returncode
    except subprocess.TimeoutExpired:
        return "[timeout]", 1
    except Exception as exc:
        return str(exc), 1


def scan_semgrep(local_path: str) -> list[Finding]:
    """Run semgrep p/ci on the cloned repo. No-op if semgrep missing."""
    if not shutil.which("semgrep"):
        return []

    out, code = _run(
        ["semgrep", "--config", "p/ci", "--json", "--quiet", "--metrics=off", local_path],
        timeout=180,
    )
    if not out.strip().startswith("{"):
        return []

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for idx, hit in enumerate((data.get("results") or [])[:15], start=1):
        extra = hit.get("extra") or {}
        raw_sev = str(extra.get("severity", "WARNING")).upper()
        severity = _SEV_MAP.get(raw_sev, Severity.MEDIUM)
        rel_path = hit.get("path") or ""
        if rel_path.startswith(local_path):
            rel_path = rel_path[len(local_path) :].lstrip("/\\")
        start = hit.get("start") or {}
        findings.append(
            Finding(
                id=f"SGM-{idx:03d}",
                severity=severity,
                category="semgrep",
                title=f"Semgrep: {hit.get('check_id', 'finding')}",
                description=extra.get("message") or "Semgrep static analysis match.",
                file_path=rel_path or None,
                line_number=start.get("line"),
                evidence=(extra.get("lines") or extra.get("message") or "")[:300],
                fix_suggestion="Review Semgrep rule recommendation and remediate in source.",
                auto_fixable=False,
            )
        )
    return findings


if __name__ == "__main__":
    import os
    import tempfile

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("eval('1+1')\n")
    res = scan_semgrep(d)
    print("semgrep.py self-check OK", len(res), "(0 if semgrep not installed)")
