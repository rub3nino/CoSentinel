import re
import subprocess

import config
from models import Finding, Severity
from scanners.secrets import EXTRA_PATTERNS


def scan_git_history(local_path: str, max_commits: int = 50) -> list[Finding]:
    """
    Run git log and scan added lines for secrets.
    Return [] on any failure.
    """
    try:
        patterns = {
            **config.SECRET_PATTERNS,
            **EXTRA_PATTERNS,
        }
        compiled = [(name, re.compile(regex)) for name, regex in patterns.items()]

        check = subprocess.run(
            ["git", "-C", local_path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            return []

        proc = subprocess.run(
            [
                "git",
                "-C",
                local_path,
                "log",
                "--oneline",
                "-n",
                str(max_commits),
                "--diff-filter=A",
                "--patch",
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []

        findings: list[Finding] = []
        counter = 1
        current_file = None

        for raw_line in proc.stdout.splitlines():
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[len("+++ b/") :].strip()
                continue
            if raw_line.startswith("--- "):
                continue
            if not raw_line.startswith("+") or raw_line.startswith("+++"):
                continue

            line = raw_line[1:]
            for pattern_name, pattern in compiled:
                for match in pattern.finditer(line):
                    evidence = match.group(0)[:6] + "***REDACTED***"
                    findings.append(
                        Finding(
                            id=f"GIT-{counter:03d}",
                            severity=Severity.CRITICAL,
                            category="secret",
                            title=f"Secret in git history: {pattern_name}",
                            description=(
                                "Credential committed to git history. Even if removed from HEAD, "
                                "it remains in git log and must be rotated immediately. "
                                "Use git-filter-repo or BFG to purge."
                            ),
                            file_path=current_file,
                            line_number=None,
                            evidence=evidence,
                            fix_suggestion=(
                                "1. Rotate credential immediately. 2. Run: git filter-repo --path <file> --invert-paths. "
                                "3. Force push all branches. 4. Notify team to re-clone."
                            ),
                            auto_fixable=False,
                        )
                    )
                    counter += 1
        return findings
    except Exception:
        return []
