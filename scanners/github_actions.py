"""GitHub Actions workflow security — CI/CD poison and supply-chain patterns."""

from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from models import Finding, Severity

# (name, regex, severity, description, fix)
RULES: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "pull_request_target trigger",
        re.compile(r"^\s*pull_request_target\s*:", re.M),
        Severity.CRITICAL,
        "Workflow runs on pull_request_target — untrusted fork code may execute with base-repo secrets.",
        "Avoid pull_request_target; use pull_request with read-only permissions or a manual approval gate.",
    ),
    (
        "Untrusted PR head checkout",
        re.compile(r"ref:\s*\${{\s*github\.event\.pull_request\.head\.(sha|ref)\s*}}", re.I),
        Severity.HIGH,
        "Checks out the PR head ref — combined with elevated permissions this enables secret exfiltration.",
        "Use actions/checkout@v4 with ref: ${{ github.event.pull_request.head.sha }} only on pull_request, not pull_request_target.",
    ),
    (
        "Script injection in run step",
        re.compile(
            r"run:\s*[^\n]*\${{\s*github\.event\.(pull_request\.(title|body|head\.ref)|issue\.(title|body)|comment\.body)",
            re.I,
        ),
        Severity.HIGH,
        "Untrusted GitHub event fields interpolated into shell run steps — classic Actions script injection.",
        "Pass values through env: with quoting; never embed ${{ github.event.* }} directly in run: scripts.",
    ),
    (
        "Workflow dispatch payload in run",
        re.compile(r"run:\s*[^\n]*\${{\s*github\.event\.(inputs|client_payload)", re.I),
        Severity.MEDIUM,
        "User-controlled workflow_dispatch input executed in a shell command.",
        "Validate and sanitize inputs; avoid shell interpolation of github.event.inputs.",
    ),
    (
        "Overbroad workflow permissions",
        re.compile(r"permissions:\s*(write-all|.*\bcontents:\s*write\b.*\bpull-requests:\s*write\b)", re.I | re.S),
        Severity.MEDIUM,
        "Workflow grants broad write permissions at job or workflow level.",
        "Apply least privilege: contents: read by default; grant write only on jobs that need it.",
    ),
    (
        "Curl pipe bash in CI",
        re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?bash", re.I),
        Severity.CRITICAL,
        "Remote script piped into bash inside CI — supply-chain takeover if the remote host is compromised.",
        "Pin scripts with checksums or vendor them in-repo; never curl|bash in production pipelines.",
    ),
    (
        "Self-hosted runner",
        re.compile(r"runs-on:\s*(\[?\s*)?self-hosted", re.I),
        Severity.MEDIUM,
        "Job targets a self-hosted runner — ensure runner isolation and secret scoping.",
        "Harden self-hosted runners; avoid running untrusted PR workflows on shared runners with secrets.",
    ),
]


def _workflow_files(all_files: list[str]) -> list[str]:
    out: list[str] = []
    for rel in all_files:
        p = rel.replace("\\", "/")
        if ".github/workflows/" not in p:
            continue
        base = os.path.basename(rel)
        if base.endswith((".yml", ".yaml")):
            out.append(rel)
    return out


def scan_github_actions(local_path: str, all_files: list[str]) -> list[Finding]:
    files = _workflow_files(all_files)
    if not files:
        return []

    counter = [0]
    lock = threading.Lock()
    findings: list[Finding] = []

    def scan_one(rel_path: str) -> list[Finding]:
        abs_path = os.path.join(local_path, rel_path)
        try:
            with open(abs_path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            return []

        local: list[Finding] = []
        for name, pattern, severity, description, fix in RULES:
            for match in pattern.finditer(text):
                lineno = text.count("\n", 0, match.start()) + 1
                line = text.splitlines()[lineno - 1] if lineno <= len(text.splitlines()) else ""
                with lock:
                    counter[0] += 1
                    fid = f"GHA-{counter[0]:03d}"
                local.append(
                    Finding(
                        id=fid,
                        severity=severity,
                        category="github_actions",
                        title=f"GitHub Actions: {name}",
                        description=description,
                        file_path=rel_path,
                        line_number=lineno,
                        evidence=line.strip()[:200],
                        fix_suggestion=fix,
                        auto_fixable=False,
                    )
                )
                break  # one finding per rule per file
        return local

    with ThreadPoolExecutor(max_workers=min(8, len(files))) as pool:
        for batch in pool.map(scan_one, files):
            findings.extend(batch)

    return findings


if __name__ == "__main__":
    import tempfile

    d = tempfile.mkdtemp()
    wf = os.path.join(d, ".github", "workflows", "ci.yml")
    os.makedirs(os.path.dirname(wf), exist_ok=True)
    with open(wf, "w", encoding="utf-8") as fh:
        fh.write("on:\n  pull_request_target:\n    types: [opened]\n")
    res = scan_github_actions(d, [".github/workflows/ci.yml"])
    assert any("pull_request_target" in f.title for f in res), res
    print("github_actions.py self-check OK", len(res))
