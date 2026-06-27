import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import config
from models import Finding, Severity

SEVERITY = {
    "Shell Injection": Severity.CRITICAL,
    "SQL Concatenation": Severity.CRITICAL,
    "SQL Injection": Severity.CRITICAL,
    "Eval Usage": Severity.CRITICAL,
    "Pickle Deserialization": Severity.CRITICAL,
    "innerHTML XSS": Severity.HIGH,
    "document.write": Severity.HIGH,
    "Child Process Shell": Severity.HIGH,
    "Exec Usage": Severity.HIGH,
    "Hardcoded Secret": Severity.HIGH,
    "Hardcoded Credential": Severity.HIGH,
    "Debug Mode": Severity.MEDIUM,
    "Hardcoded Bind All": Severity.MEDIUM,
    "Assert Auth": Severity.MEDIUM,
    "TODO Security": Severity.LOW,
    "Hardcoded IP": Severity.LOW,
    "File Inclusion": Severity.HIGH,
    "XSS Echo": Severity.HIGH,
    "Mass Assignment": Severity.MEDIUM,
    "TLS Skip Verify": Severity.MEDIUM,
    "Weak Random": Severity.LOW,
    "Curl Pipe Bash": Severity.HIGH,
    "World Writable": Severity.MEDIUM,
    "Unquoted Variable": Severity.MEDIUM,
}

RISK_DESCRIPTIONS = {
    "Shell Injection": "shell=True passes command to shell interpreter, enabling injection if any part is user-controlled",
    "SQL Concatenation": "String concatenation in SQL queries enables SQL injection attacks",
    "Eval Usage": "eval() executes arbitrary code, dangerous with any user input",
    "Exec Usage": "exec() executes arbitrary code, dangerous with any user input",
    "Pickle Deserialization": "pickle.loads() on untrusted data enables arbitrary code execution",
    "Hardcoded Bind All": "Binding to 0.0.0.0 exposes service on all interfaces including external",
    "Debug Mode": "Debug mode in production exposes stack traces and internal state",
    "Assert Auth": "assert statements are removed with -O flag, bypassing security checks",
    "innerHTML XSS": "innerHTML with dynamic content enables Cross-Site Scripting (XSS)",
    "document.write": "document.write() with dynamic content enables XSS attacks",
    "Child Process Shell": "Shell command execution with dynamic strings enables command injection",
    "Hardcoded Secret": "Hardcoded credential in source can be extracted from the repository history",
    "TODO Security": "Security-related TODO/FIXME indicates known unresolved security issue",
    "Hardcoded IP": "Hardcoded internal IP addresses reveal network topology",
    "File Inclusion": "Including paths built from user input can expose local files and enable remote code execution",
    "XSS Echo": "Echoing request data directly into HTML can trigger reflected XSS",
    "Mass Assignment": "params.permit! allows unexpected attributes to be assigned to sensitive fields",
    "TLS Skip Verify": "Disabling TLS verification enables man-in-the-middle attacks",
    "Weak Random": "math/rand is not cryptographically secure and should not protect secrets or tokens",
    "Curl Pipe Bash": "curl | bash executes remote code without inspection and can run attacker-controlled payloads",
    "World Writable": "World-writable permissions let other users modify the file or directory",
    "Unquoted Variable": "Unquoted shell variables can split on spaces and expand unexpectedly",
}

FIX_SUGGESTIONS = {
    "Shell Injection": "Remove shell=True. Use list form: subprocess.run(['cmd', 'arg'])",
    "SQL Concatenation": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
    "Eval Usage": "Replace eval() with ast.literal_eval() for data, or refactor to avoid dynamic execution",
    "Exec Usage": "Refactor to avoid exec(). If unavoidable, validate input strictly against allowlist",
    "Pickle Deserialization": "Use json.loads() instead of pickle. If pickle required, sign payloads with hmac",
    "Hardcoded Bind All": "Use 127.0.0.1 for local services. Use 0.0.0.0 only with firewall rules documented",
    "Debug Mode": "Set debug=False in production. Use environment variable: debug=os.getenv('DEBUG', 'false').lower()=='true'",
    "Assert Auth": "Replace assert with explicit if/raise: if not authenticated: raise PermissionError()",
    "innerHTML XSS": "Use textContent instead of innerHTML, or sanitize with DOMPurify",
    "document.write": "Use DOM manipulation methods: createElement, appendChild instead",
    "Child Process Shell": "Use array form: exec(['cmd', arg]) or validate/escape all dynamic parts",
    "Hardcoded Secret": "Move the credential to an environment variable and rotate it immediately",
    "TODO Security": "Resolve the security issue before deploying to production",
    "Hardcoded IP": "Move to configuration file or environment variable",
    "File Inclusion": "Use a fixed allowlist of files or map inputs to safe paths before including them",
    "XSS Echo": "Escape output before rendering or use a templating engine with auto-escaping",
    "Mass Assignment": "Replace permit! with an explicit allowlist of safe attributes",
    "TLS Skip Verify": "Enable certificate verification; pin certificates if needed instead of disabling checks",
    "Weak Random": "Use crypto/rand for secrets, tokens, and any security-sensitive randomness",
    "Curl Pipe Bash": "Download the script, inspect it, then run it explicitly",
    "World Writable": "Use the minimum required permissions, typically 755 or 644",
    "Unquoted Variable": "Quote shell variables and use safe test syntax like [ \"$var\" = value ]",
}

# Pattern names whose match contains a credential value — redact their evidence.
SECRET_NAMES = {"Hardcoded Secret", "Hardcoded Credential"}

JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
PHP_EXTS = {".php", ".phtml", ".php5", ".php7"}
RUBY_EXTS = {".rb", ".rake"}
GO_EXTS = {".go"}
BASH_EXTS = {".sh", ".bash"}

PHP_PATTERNS = {
    "SQL Injection": r"mysql_query\s*\(\s*[\"'].*\$|mysqli?_query.*\\\$",
    "Eval Usage": r"\beval\s*\(",
    "Shell Injection": r"\b(exec|shell_exec|system|passthru|popen)\s*\(\s*\$",
    "File Inclusion": r"\b(include|require|include_once|require_once)\s*\(\s*\$",
    "XSS Echo": r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
    "Hardcoded Credential": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
}

RUBY_PATTERNS = {
    "Shell Injection": r"\`.*#\{|system\s*\(.*#\{|\bexec\s+.*#\{",
    "Eval Usage": r"\beval\s*[\(\s]",
    "SQL Injection": r"\.where\s*\(\s*[\"'].*#\{|\bexecute\s*\(\s*[\"'].*#\{",
    "Mass Assignment": r"params\.permit!",
    "Hardcoded Secret": r"(?i)(secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]",
}

GO_PATTERNS = {
    "SQL Injection": r"db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf",
    "Shell Injection": r"exec\.Command\s*\(\s*\w+\s*,.*\+",
    "Hardcoded Credential": r"(?i)(password|secret|token|key)\s*:?=\s*\"[^\"]{8,}\"",
    "TLS Skip Verify": r"InsecureSkipVerify\s*:\s*true",
    "Weak Random": r"\bmath/rand\b",
}

BASH_PATTERNS = {
    "Eval Usage": r"\beval\s+[\"\\$`]",
    "Curl Pipe Bash": r"curl\s+.*\|\s*(sudo\s+)?bash",
    "Hardcoded Credential": r"(?i)(PASSWORD|SECRET|TOKEN|KEY)=[^\s$][^\s]{4,}",
    "World Writable": r"chmod\s+(a\+w|777|o\+w)",
    "Unquoted Variable": r"\[\s+\$[A-Za-z_]+\s+[=!]",
}


def _language(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".py":
        return "python"
    if ext in JS_EXTS:
        return "javascript"
    if ext in PHP_EXTS:
        return "php"
    if ext in RUBY_EXTS:
        return "ruby"
    if ext in GO_EXTS:
        return "go"
    if ext in BASH_EXTS:
        return "bash"
    return "generic"


def scan_code(local_path: str, all_files: list[str]) -> list[Finding]:
    counter = [0]
    lock = threading.Lock()
    findings: list[Finding] = []

    def scan_file(rel_path: str) -> list[Finding]:
        lang = _language(rel_path)
        local_patterns = {
            "php": PHP_PATTERNS,
            "ruby": RUBY_PATTERNS,
            "go": GO_PATTERNS,
            "bash": BASH_PATTERNS,
        }
        patterns = {
            **config.CODE_PATTERNS.get(lang, {}),
            **local_patterns.get(lang, {}),
            **config.CODE_PATTERNS["generic"],
        }
        compiled = [(name, re.compile(rx)) for name, rx in patterns.items()]
        abs_path = os.path.join(local_path, rel_path)
        out: list[Finding] = []
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    for name, rx in compiled:
                        m = rx.search(line)
                        if m:
                            with lock:
                                counter[0] += 1
                                fid = f"CODE-{counter[0]:03d}"
                            # Never echo the credential value back; redact secret-bearing matches.
                            evidence = (
                                m.group(0)[:6] + "***REDACTED***"
                                if name in SECRET_NAMES
                                else line.strip()[:200]
                            )
                            out.append(Finding(
                                id=fid,
                                severity=SEVERITY.get(name, Severity.INFO),
                                category="code",
                                title=name,
                                description=RISK_DESCRIPTIONS.get(name, name),
                                file_path=rel_path,
                                line_number=lineno,
                                evidence=evidence,
                                fix_suggestion=FIX_SUGGESTIONS.get(name, "Review and remediate this pattern"),
                                auto_fixable=False,
                            ))
        except OSError:
            pass
        return out

    with ThreadPoolExecutor(max_workers=8) as ex:
        for result in ex.map(scan_file, all_files):
            findings.extend(result)
    return findings


if __name__ == "__main__":
    # ponytail: self-check against a temp file with a known-bad pattern
    import tempfile
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "bad.py"), "w") as f:
        f.write("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    res = scan_code(d, ["bad.py"])
    assert any(f.title == "Shell Injection" and f.severity == Severity.CRITICAL for f in res), res
    print("code.py self-check OK", [f.id for f in res])
