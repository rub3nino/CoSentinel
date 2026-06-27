import os
from dotenv import load_dotenv

load_dotenv()

REGOLO_API_KEY = os.getenv("REGOLO_API_KEY", "")
REGOLO_BASE_URL = os.getenv("REGOLO_BASE_URL", "https://api.regolo.ai/v1")
REGOLO_MODEL = os.getenv("REGOLO_MODEL", "gpt-oss-120b")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Live network validation (nmap, nuclei, …) — off by default for public/hackathon deployments.
ENABLE_LIVE_SCAN = os.getenv("ENABLE_LIVE_SCAN", "false").lower() in ("1", "true", "yes")

CLONE_BASE_DIR = "/tmp/cosentinel_repos"

OSV_API_URL = "https://api.osv.dev/v1/query"

# Secret patterns — regex
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[baprs]-[a-zA-Z0-9\-]{10,}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Stripe Key": r"sk_live_[a-zA-Z0-9]{24,}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}",
}

# Dangerous code patterns per language
CODE_PATTERNS = {
    "python": {
        "Shell Injection": r"subprocess\.(call|run|Popen)\(.*shell\s*=\s*True",
        "Eval Usage": r"\beval\s*\(",
        "Exec Usage": r"\bexec\s*\(",
        "SQL Concatenation": r"(execute|cursor\.execute)\s*\(\s*[f\"].*\+",
        "Pickle Deserialization": r"pickle\.loads?\(",
        "Hardcoded Bind All": r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
        "Debug Mode": r"debug\s*=\s*True",
        "Assert Auth": r"assert\s+.*auth",
    },
    "javascript": {
        "Eval Usage": r"\beval\s*\(",
        "innerHTML XSS": r"\.innerHTML\s*=",
        "document.write": r"document\.write\s*\(",
        "SQL Concatenation": r"(query|execute)\s*\(\s*[`'\"].*\+",
        "Hardcoded Secret": r"(?i)(secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "Child Process Shell": r"exec\s*\(\s*[`'\"]",
    },
    "generic": {
        "TODO Security": r"(?i)#\s*(todo|fixme|hack|xxx).*?(auth|security|password|token|secret)",
        "Hardcoded IP": r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    },
}

# Files that indicate dangerous config
DANGEROUS_CONFIG_PATTERNS = {
    "Dockerfile": {
        "Run as root": r"USER\s+root",
        "Privileged mode hint": r"--privileged",
        "Secrets in ENV": r"ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN)\s*=",
        "Latest tag": r"FROM\s+\S+:latest",
    },
    ".github/workflows": {
        "Secrets in env": r"(?i)(password|secret|token)\s*:\s*\${{",
        "Pull request write": r"pull-requests\s*:\s*write",
        "Untrusted input in run": r"run:.*\${{.*github\.event\.pull_request",
    },
    ".env.example": {
        "Real secret in example": r"(?i)(key|secret|password|token)\s*=\s*[a-zA-Z0-9+/]{16,}",
    },
}

# Extensions to skip (binary, media, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf",
    ".zip", ".tar", ".gz", ".whl", ".egg", ".pyc", ".pyo",
    ".lock", ".sum", ".mod",
}

# Max file size to scan (bytes)
MAX_FILE_SIZE = 500_000
