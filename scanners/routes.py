import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from models import Finding, Severity

# ponytail: only flag sensitive-looking paths without auth signals in a small window — not full auth-flow analysis
SENSITIVE_PATH = re.compile(
    r"(?i)(/admin|/debug|/internal|/upload|/actuator|/metrics|/graphql|/console|"
    r"/backup|/config|/swagger|/api-docs|/manage|/private|/secret|/shell|/exec|/reset-password)"
)

AUTH_SIGNAL = re.compile(
    r"(?i)(login_required|requires_auth|@authenticated|authenticate|authorize|"
    r"get_current_user|Depends\s*\(.*auth|JWTBearer|verify_token|isAuthenticated|"
    r"ensureLoggedIn|authGuard|@UseGuards|jwt_required|IsAuthenticated|"
    r"permission_classes|csrf_protect|@login_required|@auth\.|middleware.*auth|"
    r"requireAuth|withAuth|authenticated|OAuth2PasswordBearer)"
)

ROUTE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""@(?:app|bp|blueprint|router)\.(?:route|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"""), "python"),
    (re.compile(r"""@(?:app|router)\.(?:get|post|put|patch|delete|api_route)\s*\(\s*['"]([^'"]+)['"]"""), "python"),
    (re.compile(r"""(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"""), "javascript"),
    (re.compile(r"""path\s*\(\s*['"]([^'"]+)['"]"""), "python"),
]

SKIP_PATH = re.compile(r"(?i)^/(health|healthz|ready|readyz|live|livez|ping|status|favicon\.ico)$")

SEVERITY = Severity.HIGH
DESCRIPTION = (
    "Sensitive route declared without an obvious auth guard nearby. "
    "Verify authentication and authorization before exposing this path."
)
FIX = "Add authentication middleware or decorator; restrict admin/debug routes to trusted networks."


def _scan_file(local_path: str, rel_path: str) -> list[tuple[int, str, str]]:
    ext = os.path.splitext(rel_path)[1].lower()
    if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}:
        return []
    abs_path = os.path.join(local_path, rel_path)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return []

    hits: list[tuple[int, str, str]] = []
    for idx, line in enumerate(lines):
        for pattern, lang in ROUTE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            path = match.group(1).split("{")[0].rstrip("/") or "/"
            if SKIP_PATH.match(path) or not SENSITIVE_PATH.search(path):
                continue
            window_start = max(0, idx - 15)
            window_end = min(len(lines), idx + 6)
            window = "".join(lines[window_start:window_end])
            if AUTH_SIGNAL.search(window):
                continue
            hits.append((idx + 1, path, line.strip()[:200]))
    return hits


def scan_routes(local_path: str, all_files: list[str]) -> list[Finding]:
    targets = [f for f in all_files if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"))]
    counter = [0]
    lock = threading.Lock()
    findings: list[Finding] = []

    def scan_one(rel_path: str) -> list[Finding]:
        out: list[Finding] = []
        for lineno, path, evidence in _scan_file(local_path, rel_path):
            with lock:
                counter[0] += 1
                fid = f"RTE-{counter[0]:03d}"
            out.append(
                Finding(
                    id=fid,
                    severity=SEVERITY,
                    category="route",
                    title=f"Unauthenticated sensitive route: {path}",
                    description=DESCRIPTION,
                    file_path=rel_path,
                    line_number=lineno,
                    evidence=evidence,
                    fix_suggestion=FIX,
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
        fh.write("@app.route('/admin')\ndef admin_panel():\n    return 'ok'\n")
    res = scan_routes(d, ["app.py"])
    assert res and "admin" in res[0].title, res
    print("routes.py self-check OK", res[0].title)
