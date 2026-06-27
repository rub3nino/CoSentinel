import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from models import Finding, Severity

# ponytail: pattern-only weak-auth hints — not control-flow aware
PATTERNS: list[tuple[str, Severity, str, str, re.Pattern[str]]] = [
    (
        "JWT verify disabled",
        Severity.CRITICAL,
        "JWT signature verification is disabled — tokens can be forged.",
        "Enable verify_signature and validate issuer/audience.",
        re.compile(r"(?i)verify\s*=\s*False|verify_signature\s*=\s*False|options\s*=\s*\{[^}]*verify_signature['\"]?\s*:\s*False"),
    ),
    (
        "JWT none algorithm",
        Severity.CRITICAL,
        "JWT configured to accept the 'none' algorithm.",
        "Use an explicit allowlist such as algorithms=['HS256'] or ['RS256'].",
        re.compile(r"(?i)algorithms\s*=\s*\[[^\]]*['\"]none['\"]"),
    ),
    (
        "Permissive CORS",
        Severity.HIGH,
        "Cross-origin access allows any origin — risky with credentials or sensitive APIs.",
        "Restrict Access-Control-Allow-Origin to trusted domains.",
        re.compile(r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*|cors\(.*origin\s*=\s*['\"]?\*)"),
    ),
    (
        "Default session secret",
        Severity.HIGH,
        "Session or app secret uses a known default/dev value.",
        "Load SECRET_KEY from a secret manager or environment variable.",
        re.compile(r"(?i)(SECRET_KEY|SESSION_SECRET|APP_SECRET)\s*=\s*['\"](dev|development|changeme|secret|test|password)['\"]"),
    ),
    (
        "CSRF protection disabled",
        Severity.MEDIUM,
        "CSRF protection appears disabled on a web handler.",
        "Remove csrf_exempt / csrf=False unless the endpoint is a safe read-only API with token auth.",
        re.compile(r"(?i)csrf_exempt|csrf\s*=\s*False|@csrf\.exempt"),
    ),
]

EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".rb", ".go", ".php"}


def _scan_file(local_path: str, rel_path: str) -> list[tuple[int, str, str, Severity, str, str]]:
    if os.path.splitext(rel_path)[1].lower() not in EXTS:
        return []
    abs_path = os.path.join(local_path, rel_path)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    hits: list[tuple[int, str, str, Severity, str, str]] = []
    for lineno, line in enumerate(lines, 1):
        for name, severity, desc, fix, pattern in PATTERNS:
            if pattern.search(line):
                hits.append((lineno, name, line.strip()[:200], severity, desc, fix))
    return hits


def scan_auth(local_path: str, all_files: list[str]) -> list[Finding]:
    targets = [f for f in all_files if os.path.splitext(f)[1].lower() in EXTS]
    counter = [0]
    lock = threading.Lock()
    findings: list[Finding] = []

    def scan_one(rel_path: str) -> list[Finding]:
        out: list[Finding] = []
        for lineno, name, evidence, severity, desc, fix in _scan_file(local_path, rel_path):
            with lock:
                counter[0] += 1
                fid = f"AUTH-{counter[0]:03d}"
            out.append(
                Finding(
                    id=fid,
                    severity=severity,
                    category="auth",
                    title=name,
                    description=desc,
                    file_path=rel_path,
                    line_number=lineno,
                    evidence=evidence,
                    fix_suggestion=fix,
                    auto_fixable=False,
                )
            )
        return out

    with ThreadPoolExecutor(max_workers=8) as pool:
        for batch in pool.map(scan_one, targets):
            findings.extend(batch)
    return findings


if __name__ == "__main__":
    import tempfile

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("jwt.decode(token, verify=False)\n")
    res = scan_auth(d, ["app.py"])
    assert res and res[0].title == "JWT verify disabled", res
    print("auth.py self-check OK", res[0].title)
