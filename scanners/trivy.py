import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from models import Finding, Severity

FROM_RE = re.compile(r"^\s*FROM\s+([^\s#]+)", re.IGNORECASE | re.MULTILINE)
SENSITIVE_BASE = re.compile(r":latest$|:latest@|^scratch$", re.I)


def _dockerfiles(all_files: list[str]) -> list[str]:
    out = []
    for rel in all_files:
        base = os.path.basename(rel)
        if base == "Dockerfile" or base.lower().startswith("dockerfile."):
            out.append(rel)
    return out


def _run(cmd: list[str], timeout: int = 90) -> tuple[str, int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout + proc.stderr)[:12000], proc.returncode
    except subprocess.TimeoutExpired:
        return "[timeout]", 1
    except Exception as exc:
        return str(exc), 1


def _config_findings(local_path: str, rel_path: str, counter: list[int]) -> list[Finding]:
    abs_path = os.path.join(local_path, rel_path)
    out, code = _run(
        ["trivy", "config", "--format", "json", "--quiet", abs_path],
        timeout=60,
    )
    if code != 0 or not out.strip().startswith("{"):
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for result in data.get("Results") or []:
        for mis in (result.get("Misconfigurations") or [])[:8]:
            sev = str(mis.get("Severity", "MEDIUM")).upper()
            severity = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }.get(sev, Severity.MEDIUM)
            counter[0] += 1
            findings.append(
                Finding(
                    id=f"TRV-{counter[0]:03d}",
                    severity=severity,
                    category="container",
                    title=f"Dockerfile misconfig: {mis.get('Title', 'issue')}",
                    description=mis.get("Description") or "Trivy flagged a Dockerfile misconfiguration.",
                    file_path=rel_path,
                    line_number=None,
                    evidence=(mis.get("Message") or mis.get("Title") or "")[:300],
                    fix_suggestion="Follow Trivy recommendation and pin secure base images.",
                    auto_fixable=False,
                )
            )
    return findings


def _image_findings(local_path: str, rel_path: str, counter: list[int]) -> list[Finding]:
    abs_path = os.path.join(local_path, rel_path)
    try:
        text = Path(abs_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()
    for image in FROM_RE.findall(text):
        image = image.strip().strip("'\"")
        if not image or image in seen or image.lower().startswith("as "):
            continue
        seen.add(image)

        if SENSITIVE_BASE.search(image):
            counter[0] += 1
            findings.append(
                Finding(
                    id=f"TRV-{counter[0]:03d}",
                    severity=Severity.MEDIUM,
                    category="container",
                    title=f"Unpinned or latest base image: {image}",
                    description="Using :latest or unpinned tags makes builds non-reproducible and may pull vulnerable images.",
                    file_path=rel_path,
                    line_number=None,
                    evidence=f"FROM {image}",
                    fix_suggestion="Pin to a specific digest or version tag, e.g. python:3.12-slim-bookworm@sha256:…",
                    auto_fixable=False,
                )
            )

        if not shutil.which("trivy"):
            continue

        out, code = _run(
            ["trivy", "image", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--format", "json", "--quiet", image],
            timeout=120,
        )
        if code != 0 or not out.strip().startswith("{"):
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue

        vulns = []
        for result in data.get("Results") or []:
            vulns.extend(result.get("Vulnerabilities") or [])
        if not vulns:
            continue

        top = vulns[0]
        counter[0] += 1
        findings.append(
            Finding(
                id=f"TRV-{counter[0]:03d}",
                severity=Severity.HIGH if len(vulns) > 2 else Severity.MEDIUM,
                category="container",
                title=f"Vulnerable base image: {image}",
                description=f"Trivy found {len(vulns)} HIGH/CRITICAL CVE(s) in the declared base image.",
                file_path=rel_path,
                line_number=None,
                evidence=f"{top.get('VulnerabilityID', 'CVE')}: {top.get('Title', '')}"[:300],
                fix_suggestion=f"Upgrade base image {image} to a patched tag or digest.",
                auto_fixable=False,
                cve_ids=[v.get("VulnerabilityID") for v in vulns[:5] if v.get("VulnerabilityID")],
            )
        )
    return findings


def scan_dockerfiles(local_path: str, all_files: list[str]) -> list[Finding]:
    """Scan Dockerfiles with Trivy config + optional base-image CVE check. No-op if trivy missing."""
    files = _dockerfiles(all_files)
    if not files:
        return []

    counter = [0]
    findings: list[Finding] = []
    has_trivy = bool(shutil.which("trivy"))

    for rel in files:
        if has_trivy:
            findings.extend(_config_findings(local_path, rel, counter))
        findings.extend(_image_findings(local_path, rel, counter))
    return findings


if __name__ == "__main__":
    import tempfile

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "Dockerfile"), "w", encoding="utf-8") as fh:
        fh.write("FROM python:latest\n")
    res = scan_dockerfiles(d, ["Dockerfile"])
    assert any("latest" in f.title.lower() or "misconfig" in f.title.lower() for f in res) or not shutil.which("trivy"), res
    print("trivy.py self-check OK", len(res), "findings")
