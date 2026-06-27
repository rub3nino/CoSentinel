# CoSentinel — Prompt per CODEX (Builder A)

Incolla questo prompt intero in Codex per iniziare.

---

## PROMPT DA INCOLLARE IN CODEX

```
You are Builder A for CoSentinel, an AI-powered GitHub repository security scanner.
Project path: /Users/ruben/Progetti/CoSentinel/

Read AGENTS.md first for coding standards (graphify knowledge graph + ponytail lazy-dev rules).
Read models.py and config.py — these are the shared data contracts. Do NOT modify them.

Your job: implement 3 Python modules. Build them in order A1 → A2 → A3.
After each file, confirm it is written and move to the next immediately.

---

### A1: fetcher.py

Create /Users/ruben/Progetti/CoSentinel/fetcher.py

This module clones a GitHub repository locally and returns file lists.

```python
# Exact function signatures to implement:

def fetch_repo(repo_url: str, github_token: str = "") -> tuple[str, str]:
    """
    Clone repo to /tmp/cosentinel_repos/<reponame>_<timestamp>/
    If github_token provided, inject into URL: https://token@github.com/owner/repo
    Returns (local_path, repo_name).
    Raises ValueError for invalid GitHub URLs.
    Raises RuntimeError if git clone fails.
    Use subprocess to run: git clone <url> <dest>
    """

def list_repo_files(local_path: str) -> list[str]:
    """
    Walk local_path recursively.
    Return file paths relative to local_path.
    Skip: directories named .git, node_modules, __pycache__, .venv, venv, dist, build, .next, target
    Skip: files with extensions in config.SKIP_EXTENSIONS
    Skip: files larger than config.MAX_FILE_SIZE bytes
    """

def cleanup_repo(local_path: str) -> None:
    """Delete the cloned directory with shutil.rmtree."""
```

Use only: os, subprocess, shutil, pathlib, time (stdlib). Import config for constants.
After writing, add a quick self-test at the bottom inside `if __name__ == "__main__":` that prints "fetcher OK".

---

### A2: scanners/deps.py

Create /Users/ruben/Progetti/CoSentinel/scanners/deps.py

Scans dependency files in a cloned repo and finds CVEs via OSV.dev public API.

```python
from models import Finding, Severity

def scan_dependencies(local_path: str) -> list[Finding]:
    """
    1. Detect dependency files:
       - requirements.txt  → parse "package==version" lines
       - package.json      → parse JSON, read "dependencies" + "devDependencies"
       - pom.xml           → regex parse <groupId>:<artifactId>:<version>
       - go.mod            → parse "require" block lines
       - Gemfile.lock      → parse "    GEM (version)" lines

    2. For each (package, version, ecosystem), query OSV.dev:
       POST https://api.osv.dev/v1/query
       Headers: {"Content-Type": "application/json"}
       Body: {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
       Ecosystems: PyPI (requirements.txt), npm (package.json), Maven (pom.xml), Go (go.mod), RubyGems (Gemfile.lock)

    3. Parse OSV response:
       response["vulns"] → list of vulnerabilities
       Each vuln has: id, summary, severity[].score (CVSS)
       Map CVSS score: >=9.0 CRITICAL, >=7.0 HIGH, >=4.0 MEDIUM, else LOW
       If no score, default MEDIUM.

    4. For each vuln found, return a Finding:
       id = f"DEP-{counter:03d}"
       severity = mapped from CVSS
       category = "dependency"
       title = f"{package}: {vuln['summary'][:80]}"
       description = f"Package {package} version {version} has known vulnerability: {vuln['id']}"
       file_path = relative path to the dependency file
       line_number = None
       evidence = vuln["id"]  (CVE or GHSA id)
       cve_ids = [alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")]
       fix_suggestion = get fixed version from vuln["affected"][0]["ranges"] if available, else "Upgrade to latest version"
       auto_fixable = True if fixed version found else False
    """
```

Use ThreadPoolExecutor(max_workers=10) for parallel OSV queries.
Use only: requests, json, concurrent.futures, os, re (all available).
Import: from models import Finding, Severity
Import: import config

---

### A3: scanners/secrets.py

Create /Users/ruben/Progetti/CoSentinel/scanners/secrets.py

Scans all files in the repo for hardcoded secrets and credentials.

```python
from models import Finding, Severity

def scan_secrets(local_path: str, all_files: list[str]) -> list[Finding]:
    """
    For each file in all_files:
      - Read file content line by line
      - Apply each pattern from config.SECRET_PATTERNS (dict: name -> regex)
      - Skip files ending in: .md, .txt, .rst (docs often show example keys)
      - Special case: .env.example files → still scan but mark severity as LOW (not real secrets)

    For each regex match:
      id = f"SEC-{counter:03d}"
      severity:
        - CRITICAL: pattern names containing "Private Key", "AWS Secret"
        - HIGH: all others
        - LOW: if file is .env.example or .env.sample
      category = "secret"
      title = f"{pattern_name} detected"
      description = "Hardcoded credential found in source code. If this is a real credential, it must be rotated immediately."
      file_path = relative path
      line_number = line number (1-indexed)
      evidence = first_6_chars_of_match + "***REDACTED***"  (never log full secret)
      fix_suggestion = "Remove from code. Add file to .gitignore. Rotate the credential. Use environment variables instead."
      auto_fixable = False

    Use ThreadPoolExecutor(max_workers=8) for parallel file scanning.
    """
```

Use only: re, os, concurrent.futures (stdlib) + config, models.

---

When all 3 files are written, run:
```bash
cd /Users/ruben/Progetti/CoSentinel
python3 fetcher.py
python3 -c "from scanners.deps import scan_dependencies; print('deps OK')"
python3 -c "from scanners.secrets import scan_secrets; print('secrets OK')"
```
Report any errors back.
```

---

## Architettura CoSentinel — Riferimento Rapido per Codex

```
CoSentinel/
├── models.py          ← DATA CONTRACTS (non modificare)
│   ├── Finding        ← ogni vulnerabilità trovata
│   │   ├── id: str                  "DEP-001", "SEC-003", "CODE-012"
│   │   ├── severity: Severity       CRITICAL/HIGH/MEDIUM/LOW/INFO
│   │   ├── category: str            "dependency"/"secret"/"code"/"config"
│   │   ├── title: str
│   │   ├── description: str
│   │   ├── file_path: str|None      path relativo alla root del repo
│   │   ├── line_number: int|None
│   │   ├── evidence: str            snippet o CVE id (MAI secret completo)
│   │   ├── cve_ids: list[str]
│   │   ├── fix_suggestion: str
│   │   ├── auto_fixable: bool       True = PR può fixarlo automaticamente
│   │   └── fix_patch: str|None      unified diff se auto_fixable
│   │
│   └── ScanResult
│       ├── repo_url: str
│       ├── repo_name: str
│       ├── local_path: str
│       ├── findings: list[Finding]
│       └── scan_errors: list[str]
│
├── config.py          ← COSTANTI (non modificare)
│   ├── REGOLO_API_KEY, REGOLO_BASE_URL, REGOLO_MODEL
│   ├── GITHUB_TOKEN
│   ├── CLONE_BASE_DIR = "/tmp/cosentinel_repos"
│   ├── OSV_API_URL = "https://api.osv.dev/v1/query"
│   ├── SECRET_PATTERNS   dict{name: regex}  — 10 pattern
│   ├── CODE_PATTERNS     dict{lang: dict{name: regex}}
│   ├── DANGEROUS_CONFIG_PATTERNS  dict{filename: dict{name: regex}}
│   ├── SKIP_EXTENSIONS   set di estensioni binarie da saltare
│   └── MAX_FILE_SIZE = 500_000  (bytes)
│
├── fetcher.py         ← TUO TASK A1
│   ├── fetch_repo(url, token) -> (local_path, repo_name)
│   ├── list_repo_files(local_path) -> list[str]  (paths relativi)
│   └── cleanup_repo(local_path) -> None
│
└── scanners/
    ├── deps.py        ← TUO TASK A2
    │   └── scan_dependencies(local_path) -> list[Finding]
    │       Legge: requirements.txt, package.json, pom.xml, go.mod, Gemfile.lock
    │       API: POST https://api.osv.dev/v1/query per ogni package
    │
    └── secrets.py     ← TUO TASK A3
        └── scan_secrets(local_path, all_files) -> list[Finding]
            Applica config.SECRET_PATTERNS su ogni file
            Evidence sempre REDACTED (mai secret completo)
```

## Pipeline completa (per capire il contesto)

```
GitHub URL + token
      ↓
fetcher.fetch_repo()          ← TUO CODICE
      ↓
fetcher.list_repo_files()     ← TUO CODICE
      ↓ (parallelo)
deps.scan_dependencies()      ← TUO CODICE
secrets.scan_secrets()        ← TUO CODICE
code.scan_code()              ← Builder B
config_audit.scan_config()    ← Builder B
      ↓
agent.analyze()               ← Builder B (Regolo AI)
      ↓
server.py                     ← Builder B (FastAPI)
static/index.html             ← Builder B (UI)
      ↓
pr_creator.py                 ← Main brain (questo terminale)
```

## Regole di codice (AGENTS.md)

1. **Non modificare** `models.py` e `config.py`
2. **Ponytail**: scrivi il minimo. Se stdlib lo fa, usa stdlib. No astrazione non richiesta.
3. **Graphify**: se hai dubbi sui tipi, chiedi al grafo: `graphify query "cosa contiene Finding"`
4. **Import obbligatori**: `from models import Finding, Severity` + `import config`
5. **Thread safety**: usa `threading.Lock()` per i counter degli id (DEP-001, SEC-002...)
6. **Mai loggare secrets completi**: evidence sempre troncata a 6 char + "***REDACTED***"
