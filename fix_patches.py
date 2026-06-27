"""Generate and validate mechanical auto-fix patches for PR creation."""

from __future__ import annotations

import difflib
import os
import re
from pathlib import Path

from models import Finding

_HUNK = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def issue_name(title: str) -> str:
    """Normalize scanner titles to a fix rule key."""
    if ": " in title:
        title = title.split(": ", 1)[-1]
    if title.endswith(" detected"):
        title = title[: -len(" detected")]
    return title.strip()


def apply_unified_diff(content: str, patch: str) -> str | None:
    """Apply a single-file unified diff. Returns None if patch cannot be applied."""
    if not patch or not patch.strip():
        return None
    lines = content.splitlines(keepends=True)
    if content and not lines:
        lines = [content]
    out: list[str] = []
    src = 0
    i = 0
    patch_lines = patch.splitlines()
    while i < len(patch_lines):
        line = patch_lines[i]
        if line.startswith("---") or line.startswith("+++"):
            i += 1
            continue
        if line.startswith("@@"):
            m = _HUNK.search(line)
            if not m:
                return None
            start = int(m.group(1)) - 1
            if start < src or start > len(lines):
                return None
            out.extend(lines[src:start])
            src = start
            i += 1
            continue
        if line.startswith("-"):
            if src >= len(lines) or lines[src].rstrip("\n\r") != line[1:]:
                return None
            src += 1
        elif line.startswith("+"):
            addition = line[1:]
            if not addition.endswith("\n"):
                addition += "\n"
            out.append(addition)
        elif line.startswith(" "):
            if src >= len(lines) or lines[src].rstrip("\n\r") != line[1:]:
                return None
            out.extend(lines[src : src + 1])
            src += 1
        i += 1
    out.extend(lines[src:])
    return "".join(out)


def validate_patch(original: str, patch: str) -> bool:
    """Round-trip check: patch must apply cleanly and change content."""
    try:
        updated = apply_unified_diff(original, patch)
        return updated is not None and updated != original
    except Exception:
        return False


def can_fix(finding: Finding) -> bool:
    return bool(finding.auto_fixable and finding.fix_patch and finding.file_path)


def _severity_rank(severity) -> int:
    from models import Severity

    order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    return order.get(severity, 0)


def select_pr_candidates(findings: list[Finding], limit: int = 2) -> list[Finding]:
    """Pick the smallest useful PR bundle from validated mechanical fixes."""
    fixable = [f for f in findings if can_fix(f)]
    fixable.sort(
        key=lambda f: (
            -_severity_rank(f.severity),
            f.file_path or "",
            f.line_number or 0,
            f.id,
        )
    )
    return fixable[:limit]


def _unified_diff(path: str, original: str, updated: str) -> str | None:
    if original == updated:
        return None
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    )
    patch = "\n".join(diff)
    return patch if patch.strip() else None


def _replace_once(content: str, old: str, new: str) -> str | None:
    if old not in content:
        return None
    return content.replace(old, new, 1)


def _replace_regex_once(content: str, pattern: str, replacement: str) -> str | None:
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count == 0 or updated == content:
        return None
    return updated


def _remove_line(content: str, needle: str) -> str | None:
    lines = content.splitlines(keepends=True)
    updated = [line for line in lines if needle not in line]
    if len(updated) == len(lines):
        return None
    return "".join(updated)


def _fix_line(content: str, line_number: int | None, transform) -> str | None:
    if not line_number or line_number < 1:
        return None
    lines = content.splitlines(keepends=True)
    if line_number > len(lines):
        return None
    idx = line_number - 1
    new_line = transform(lines[idx])
    if new_line == lines[idx]:
        return None
    lines[idx] = new_line
    return "".join(lines)


def _mask_env_secret(content: str) -> str | None:
    updated, count = re.subn(
        r"(?m)^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(['\"]?)[^#\n\r]+(\2)",
        r"\1\g<2>CHANGE_ME\3",
        content,
        count=1,
    )
    if count == 0 or updated == content:
        return None
    return updated


def _propose_fix(original: str, finding: Finding) -> str | None:
    issue = issue_name(finding.title)
    path = finding.file_path or ""
    lineno = finding.line_number

    if issue in {"Hardcoded Bind All", "Public bind on all interfaces", "Exposed on all interfaces"}:
        line_fix = _fix_line(original, lineno, lambda ln: ln.replace("0.0.0.0", "127.0.0.1"))
        return line_fix or _replace_once(original, "0.0.0.0", "127.0.0.1")

    if issue == "Shell Injection" and path.endswith(".py"):
        line_fix = _fix_line(original, lineno, lambda ln: re.sub(r"shell\s*=\s*True", "shell=False", ln, count=1))
        return line_fix or _replace_regex_once(original, r"shell\s*=\s*True", "shell=False")

    if issue == "Debug Mode":
        def _debug_line(ln: str) -> str:
            for old, new in (
                ("debug=True", "debug=False"),
                ("debug = True", "debug = False"),
                ('["DEBUG"] = True', '["DEBUG"] = False'),
                ("['DEBUG'] = True", "['DEBUG'] = False"),
                ("DEBUG = True", "DEBUG = False"),
            ):
                if old in ln:
                    return ln.replace(old, new)
            return ln

        line_fix = _fix_line(original, lineno, _debug_line)
        return (
            line_fix
            or _replace_once(original, "debug=True", "debug=False")
            or _replace_once(original, "debug = True", "debug = False")
        )

    if issue in {"Privileged Container", "Privileged mode hint"}:
        line_fix = _fix_line(
            original,
            lineno,
            lambda ln: "" if "privileged: true" in ln.lower() or "--privileged" in ln else ln,
        )
        if line_fix is not None:
            return line_fix
        return _remove_line(original, "privileged: true") or _remove_line(original, "--privileged")

    if issue == "World Writable":
        line_fix = _fix_line(
            original,
            lineno,
            lambda ln: ln.replace("chmod 777", "chmod 755").replace("chmod a+w", "chmod u+w").replace("chmod o+w", "chmod u+w"),
        )
        return (
            line_fix
            or _replace_once(original, "chmod 777", "chmod 755")
            or _replace_once(original, "chmod a+w", "chmod u+w")
            or _replace_once(original, "chmod o+w", "chmod u+w")
        )

    if issue == "Unquoted Variable":
        line_fix = _fix_line(
            original,
            lineno,
            lambda ln: re.sub(r"\[\s+\$([A-Za-z_][A-Za-z0-9_]*)\s+([=!])", r'[ "$\1" \2', ln, count=1),
        )
        if line_fix is not None:
            return line_fix
        updated = re.subn(r"\[\s+\$([A-Za-z_][A-Za-z0-9_]*)\s+([=!])", r'[ "$\1" \2', original, count=1)[0]
        return updated if updated != original else None

    if issue == "TLS Skip Verify":
        line_fix = _fix_line(original, lineno, lambda ln: ln.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false"))
        return line_fix or _replace_once(original, "InsecureSkipVerify: true", "InsecureSkipVerify: false")

    if issue == "Latest tag" and ("dockerfile" in path.lower()):
        line_fix = _fix_line(original, lineno, lambda ln: re.sub(r":latest\b", ":3.12-slim", ln, count=1, flags=re.I))
        return line_fix or _replace_regex_once(original, r"(:latest\b)", ":3.12-slim")

    if path.endswith((".env.example", ".env.sample", ".env.test")) and any(
        token in issue for token in ("Secret", "Key", "Token", "Credential", "Password", "Generic")
    ):
        return _mask_env_secret(original)

    return None


def attach_fix_patches(local_path: str, findings: list[Finding]) -> None:
    """Attach validated unified-diff patches to findings that have safe mechanical fixes."""
    cache: dict[str, str] = {}

    def read_file(rel_path: str) -> str | None:
        if rel_path in cache:
            return cache[rel_path]
        abs_path = os.path.join(local_path, rel_path)
        try:
            text = Path(abs_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        cache[rel_path] = text
        return text

    for finding in findings:
        if finding.fix_patch or not finding.file_path:
            continue
        original = read_file(finding.file_path)
        if original is None:
            continue
        updated = _propose_fix(original, finding)
        if not updated or updated == original:
            continue
        patch = _unified_diff(finding.file_path, original, updated)
        if patch and validate_patch(original, patch):
            finding.fix_patch = patch
            finding.auto_fixable = True
        else:
            finding.auto_fixable = False
            finding.fix_patch = None


if __name__ == "__main__":
    orig = "services:\n  web:\n    ports:\n      - '0.0.0.0:8080:8080'\n"
    f = Finding(
        id="EXP-001",
        severity=__import__("models").Severity.HIGH,
        category="exposure",
        title="docker-compose: Public bind on all interfaces",
        description="x",
        file_path="docker-compose.yml",
        line_number=4,
        evidence="0.0.0.0:8080",
        fix_suggestion="bind localhost",
        auto_fixable=False,
    )
    upd = _propose_fix(orig, f)
    assert upd and "127.0.0.1" in upd, upd
    patch = _unified_diff(f.file_path, orig, upd)
    assert patch and validate_patch(orig, patch), patch
    picks = select_pr_candidates([f, f], limit=2)
    assert len(picks) == 1 or len(picks) == 2, picks
    print("fix_patches.py self-check OK")
