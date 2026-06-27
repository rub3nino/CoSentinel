# CoSentinel — CODEX Backend V2

Project: /Users/ruben/Progetti/CoSentinel/
Read AGENTS.md before starting (graphify + ponytail rules).
Do NOT modify models.py. Do NOT touch server.py, agent.py, static/.

Your job: extend the backend scanners and fetcher. Work in order C1 → C2 → C3 → C4.

---

## C1: Extend `scanners/code.py` — add PHP, Ruby, Go, Bash patterns

Open scanners/code.py and add support for more languages.

Add to the language detection logic:
```
.php → "php"
.rb  → "ruby"
.go  → "go"
.sh .bash → "bash"
```

Add these pattern dicts inside the file (do not touch config.py):

```python
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
    "SQL Injection": r'db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf',
    "Shell Injection": r'exec\.Command\s*\(\s*\w+\s*,.*\+',
    "Hardcoded Credential": r'(?i)(password|secret|token|key)\s*:?=\s*"[^"]{8,}"',
    "TLS Skip Verify": r'InsecureSkipVerify\s*:\s*true',
    "Weak Random": r'\bmath/rand\b',
}

BASH_PATTERNS = {
    "Eval Usage": r'\beval\s+["\$`]',
    "Curl Pipe Bash": r'curl\s+.*\|\s*(sudo\s+)?bash',
    "Hardcoded Credential": r'(?i)(PASSWORD|SECRET|TOKEN|KEY)=[^\s$][^\s]{4,}',
    "World Writable": r'chmod\s+(a\+w|777|o\+w)',
    "Unquoted Variable": r'\[\s+\$[A-Za-z_]+\s+[=!]',
}
```

Update RISK_DESCRIPTIONS and FIX_SUGGESTIONS dicts to include all new pattern names.
Update language detection to route these new extensions to the right pattern dict.

After edit, run:
```bash
python3 -c "from scanners.code import scan_code; print('code extended OK')"
```

---

## C2: Extend `scanners/secrets.py` — add more patterns

Open scanners/secrets.py and add these patterns to the existing SECRET_PATTERNS-equivalent logic inside the file:

```python
EXTRA_PATTERNS = {
    "OpenAI Key":       r"sk-[a-zA-Z0-9]{20,}",
    "Anthropic Key":    r"sk-ant-[a-zA-Z0-9\-_]{20,}",
    "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Config":  r"firebase.*apiKey.*:.*['\"][A-Za-z0-9\-_]{20,}['\"]",
    "Heroku API Key":   r"[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Twilio Key":       r"SK[0-9a-fA-F]{32}",
    "Azure Conn String":r"DefaultEndpointsProtocol=https;AccountName=",
    "DB Conn String":   r"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]{4,}@",
    "NPM Token":        r"npm_[a-zA-Z0-9]{36}",
    "Vault Token":      r"hvs\.[a-zA-Z0-9]{24,}",
}
```

Merge these into whatever dict/list the existing scan_secrets() uses for pattern matching.
Keep the same redaction logic (first 6 chars + ***REDACTED***).
Severity for OpenAI/Anthropic keys: CRITICAL (same as AWS).

After edit:
```bash
python3 -c "from scanners.secrets import scan_secrets; print('secrets extended OK')"
```

---

## C3: Add `scanners/git_history.py` — scan git log for accidentally committed secrets

Create /Users/ruben/Progetti/CoSentinel/scanners/git_history.py

```python
from models import Finding, Severity
import subprocess, re, config

def scan_git_history(local_path: str, max_commits: int = 50) -> list[Finding]:
    """
    Run: git log --oneline -n {max_commits} --diff-filter=A --patch
    in local_path.
    Search each added line (+) in the diff for config.SECRET_PATTERNS.
    Also search for EXTRA_PATTERNS from secrets.py (import them).

    For each match:
      id = f"GIT-{counter:03d}"
      severity = CRITICAL (secrets in git history are permanent until repo scrubbed)
      category = "secret"
      title = f"Secret in git history: {pattern_name}"
      description = "Credential committed to git history. Even if removed from HEAD,
                     it remains in git log and must be rotated immediately.
                     Use git-filter-repo or BFG to purge."
      file_path = filename from diff header
      line_number = None
      evidence = first_6_chars + "***REDACTED***"
      fix_suggestion = "1. Rotate credential immediately. 2. Run: git filter-repo --path <file> --invert-paths. 3. Force push all branches. 4. Notify team to re-clone."
      auto_fixable = False

    Return list[Finding]. Return [] if git not available or repo has no history.
    Never crash — wrap everything in try/except.
    """
```

After writing:
```bash
python3 -c "from scanners.git_history import scan_git_history; print('git_history OK')"
```

---

## C4: Update `server.py` — add git_history to pipeline + add /api/health endpoint

Open server.py.

1. In the POST /api/scan handler, after the 4 parallel scans, add:
   ```python
   from scanners.git_history import scan_git_history
   git_findings = scan_git_history(local_path)
   ```
   Include git_findings in the combined findings list.

2. Add a new endpoint:
   ```python
   @app.get("/api/health")
   async def health():
       return {
           "status": "ok",
           "model": config.REGOLO_MODEL,
           "scanners": ["deps", "secrets", "code", "config", "git_history"]
       }
   ```

3. Update the stats in the scan response to include:
   ```python
   "git_findings": len(git_findings)
   ```

After edit:
```bash
python3 -c "import server; print('server updated OK')"
curl http://localhost:8000/api/health  # if server is running
```

---

## Summary of what Codex owns
- scanners/deps.py        (done + maintained)
- scanners/secrets.py     (done + extended in C2)
- fetcher.py              (done + maintained)
- scanners/code.py        (done + extended in C1)
- scanners/git_history.py (new — C3)
- server.py backend logic (C4 additions only)

Do NOT touch: agent.py, static/index.html, pr_creator.py, models.py, config.py
