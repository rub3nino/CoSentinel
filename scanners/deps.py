import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import config
import requests
from models import Finding, Severity


def _parse_requirements(text: str) -> list[tuple[str, str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;#]+)", line)
        if match:
            out.append((match.group(1), match.group(2), "PyPI"))
    return out


def _parse_package_json(text: str) -> list[tuple[str, str, str]]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            if isinstance(version, str):
                version = version.lstrip("^~><= ")
                out.append((name, version, "npm"))
    return out


def _parse_pom_xml(text: str) -> list[tuple[str, str, str]]:
    out = []
    pattern = re.compile(
        r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>",
        re.S,
    )
    for group_id, artifact_id, version in pattern.findall(text):
        out.append((f"{group_id}:{artifact_id}", version.strip(), "Maven"))
    return out


def _parse_go_mod(text: str) -> list[tuple[str, str, str]]:
    out = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        match = re.match(r"^(\S+)\s+([^\s]+)", line)
        if match:
            out.append((match.group(1), match.group(2), "Go"))
    return out


def _parse_gemfile_lock(text: str) -> list[tuple[str, str, str]]:
    out = []
    for name, version in re.findall(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", text, re.M):
        out.append((name, version.strip(), "RubyGems"))
    return out


def _find_dependency_files(local_path: str) -> list[str]:
    targets = {"requirements.txt", "package.json", "pom.xml", "go.mod", "Gemfile.lock"}
    paths = []
    for root, dirs, files in os.walk(local_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}]
        for filename in files:
            if filename in targets:
                paths.append(os.path.join(root, filename))
    return paths


def _extract_fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []) or []:
        for version_range in affected.get("ranges", []) or []:
            for event in version_range.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _severity_from_vuln(vuln: dict) -> Severity:
    scores = []
    for item in vuln.get("severity", []) or []:
        score = item.get("score", "")
        match = re.search(r"(\d+(?:\.\d+)?)", str(score))
        if match:
            scores.append(float(match.group(1)))
    score = max(scores) if scores else None
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _query_osv(package: str, version: str, ecosystem: str) -> list[dict]:
    response = requests.post(
        config.OSV_API_URL,
        headers={"Content-Type": "application/json"},
        json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("vulns", []) or []


def scan_dependencies(local_path: str) -> list[Finding]:
    dependency_files = _find_dependency_files(local_path)
    packages: list[tuple[str, str, str, str]] = []

    for file_path in dependency_files:
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        name = Path(file_path).name
        if name == "requirements.txt":
            parsed = _parse_requirements(text)
        elif name == "package.json":
            parsed = _parse_package_json(text)
        elif name == "pom.xml":
            parsed = _parse_pom_xml(text)
        elif name == "go.mod":
            parsed = _parse_go_mod(text)
        else:
            parsed = _parse_gemfile_lock(text)
        for package, version, ecosystem in parsed:
            packages.append((file_path, package, version, ecosystem))

    unique = list(dict.fromkeys(packages))
    findings: list[Finding] = []

    def work(item: tuple[str, str, str, str]) -> tuple[tuple[str, str, str, str], list[dict]]:
        file_path, package, version, ecosystem = item
        try:
            return item, _query_osv(package, version, ecosystem)
        except Exception:
            return item, []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(work, item) for item in unique]
        results = []
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: (item[0][0], item[0][1], item[0][2]))
    counter = 1
    for (file_path, package, version, _ecosystem), vulns in results:
        rel_path = os.path.relpath(file_path, local_path).replace(os.sep, "/")
        for vuln in vulns:
            fixed_version = _extract_fixed_version(vuln)
            cve_ids = [alias for alias in vuln.get("aliases", []) or [] if str(alias).startswith("CVE-")]
            findings.append(
                Finding(
                    id=f"DEP-{counter:03d}",
                    severity=_severity_from_vuln(vuln),
                    category="dependency",
                    title=f"{package}: {(vuln.get('summary') or vuln.get('id') or 'Vulnerability')[:80]}",
                    description=f"Package {package} version {version} has known vulnerability: {vuln.get('id', 'unknown')}",
                    file_path=rel_path,
                    line_number=None,
                    evidence=str(vuln.get("id", "")),
                    cve_ids=cve_ids,
                    fix_suggestion=(
                        f"Upgrade {package} from {version} to {fixed_version}"
                        if fixed_version
                        else "Upgrade to latest version"
                    ),
                    auto_fixable=bool(fixed_version),
                )
            )
            counter += 1
    return findings
