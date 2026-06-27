# CoSentinel — Builder Prompts

Project root: `/Users/ruben/Progetti/estera/CoSentinel/`

Read `models.py` and `config.py` before starting — they define shared data contracts.

---

## CODEX — Builder A

### TASK A1: `fetcher.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/fetcher.py`.

Read first: `models.py`, `config.py`

Implement a module that clones a GitHub repository locally and returns metadata.

Requirements:
- Function: `fetch_repo(repo_url: str, github_token: str = "") -> tuple[str, str]`
  - Returns: (local_path, repo_name)
  - Supports both public repos and private repos (inject token into URL if provided)
  - Clones into `config.CLONE_BASE_DIR / repo_name_timestamp`
  - If already cloned (same path exists), do `git pull` instead
  - Raises `ValueError` for invalid GitHub URLs
  - Raises `RuntimeError` if clone fails

- Function: `cleanup_repo(local_path: str) -> None`
  - Deletes the cloned directory

- Function: `list_repo_files(local_path: str) -> list[str]`
  - Returns all file paths relative to repo root
  - Skips files in `config.SKIP_EXTENSIONS`
  - Skips files larger than `config.MAX_FILE_SIZE`
  - Skips hidden directories (.git, .svn, node_modules, __pycache__, .venv, venv, dist, build)

Use only stdlib + gitpython (already installed). No other dependencies.
```

---

### TASK A2: `scanners/deps.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/scanners/deps.py`.

Read first: `models.py`, `config.py`

Implement a dependency vulnerability scanner using the OSV.dev public API.

Requirements:
- Function: `scan_dependencies(local_path: str) -> list[Finding]`
  - Detects and parses these dependency files:
    - `requirements.txt` → Python packages
    - `package.json` → npm packages (parse "dependencies" and "devDependencies")
    - `pom.xml` → Maven (parse groupId:artifactId:version)
    - `go.mod` → Go modules
    - `Gemfile.lock` → Ruby gems
  - For each package+version found, query OSV.dev:
    POST https://api.osv.dev/v1/query
    Body: {"package": {"name": "packagename", "ecosystem": "PyPI"}, "version": "1.0.0"}
    Ecosystems: PyPI, npm, Maven, Go, RubyGems
  - Map OSV severity to our Severity enum:
    CRITICAL/HIGH/MEDIUM/LOW based on CVSS score in OSV response
  - Return one Finding per CVE found with:
    - id: f"DEP-{counter:03d}"
    - category: "dependency"
    - file_path: relative path to the dependency file
    - evidence: CVE id + summary
    - cve_ids: list of CVE ids from OSV response
    - fix_suggestion: f"Upgrade {package} from {current_version} to {fixed_version}"
    - auto_fixable: True if there is a fixed version available

Use only stdlib + requests (already installed).
Batch OSV queries with threading (ThreadPoolExecutor, max 10 workers) for speed.
```

---

### TASK A3: `scanners/secrets.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/scanners/secrets.py`.

Read first: `models.py`, `config.py`

Implement a secret/credential detector that scans all files in the repository.

Requirements:
- Function: `scan_secrets(local_path: str, all_files: list[str]) -> list[Finding]`
  - `all_files` is the list from `fetcher.list_repo_files()`
  - Scan each file line by line
  - Apply all regex patterns from `config.SECRET_PATTERNS`
  - Skip files in `config.SKIP_EXTENSIONS`
  - Skip `.env.example` files (those are expected to have dummy values — handle separately)
  - For each match return a Finding with:
    - id: f"SEC-{counter:03d}"
    - severity: Severity.CRITICAL for private keys and AWS keys, Severity.HIGH for others
    - category: "secret"
    - title: pattern name (e.g. "AWS Access Key detected")
    - description: explain the risk of exposed credential
    - file_path: relative file path
    - line_number: line where match found
    - evidence: redacted match (show first 6 chars + "***" — never expose full secret)
    - fix_suggestion: "Remove from code, rotate the credential immediately, add to .gitignore"
    - auto_fixable: False (secrets require human rotation)

Performance: use concurrent.futures.ThreadPoolExecutor for parallel file scanning.
```

---

## CLAUDE CODE (other terminal) — Builder B

### TASK B1: `scanners/code.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/scanners/code.py`.

Read first: `models.py`, `config.py`

Implement a source code security pattern scanner.

Requirements:
- Function: `scan_code(local_path: str, all_files: list[str]) -> list[Finding]`
  - `all_files` is the list from `fetcher.list_repo_files()`
  - Detect file language by extension:
    - .py → "python"
    - .js .ts .jsx .tsx → "javascript"
    - all others → "generic"
  - Apply patterns from `config.CODE_PATTERNS[language]` + `config.CODE_PATTERNS["generic"]`
  - Scan line by line with regex
  - For each match return a Finding with:
    - id: f"CODE-{counter:03d}"
    - severity: 
      - CRITICAL: Shell Injection, SQL Concatenation, Eval Usage, Pickle
      - HIGH: innerHTML XSS, document.write, Child Process Shell
      - MEDIUM: Debug Mode, Hardcoded Bind All
      - LOW: TODO Security, Hardcoded IP, Assert Auth
    - category: "code"
    - title: pattern name
    - description: explain why this is dangerous
    - file_path: relative path
    - line_number: line number
    - evidence: the matching line (stripped)
    - fix_suggestion: specific fix for each pattern type
    - auto_fixable: False

Use concurrent.futures.ThreadPoolExecutor for parallel file scanning.
```

---

### TASK B2: `scanners/config_audit.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/scanners/config_audit.py`.

Read first: `models.py`, `config.py`

Implement a configuration file security auditor.

Requirements:
- Function: `scan_config(local_path: str, all_files: list[str]) -> list[Finding]`
  - Scan files that match these patterns:
    - Any file named `Dockerfile` or `Dockerfile.*`
    - Any file under `.github/workflows/` (*.yml, *.yaml)
    - Any file named `.env.example` or `.env.sample`
    - `docker-compose.yml` / `docker-compose.yaml`
    - `nginx.conf`, `apache2.conf`, `httpd.conf`
    - `kubernetes/*.yaml`, `k8s/*.yaml`, `helm/**/*.yaml`

  - Apply patterns from `config.DANGEROUS_CONFIG_PATTERNS` for known file types
  - For docker-compose: also check for `privileged: true`, missing resource limits, exposed ports
  - For each match return a Finding with:
    - id: f"CFG-{counter:03d}"
    - severity: HIGH for secrets in config, MEDIUM for misconfigs, LOW for best-practice issues
    - category: "config"
    - title: descriptive title
    - description: explain risk in context of the specific config file
    - file_path: relative path
    - line_number: line number
    - evidence: matching line stripped
    - fix_suggestion: specific remediation for that config type
    - auto_fixable: False
```

---

### TASK B3: `agent.py`

```
Create the file `/Users/ruben/Progetti/estera/CoSentinel/agent.py`.

Read first: `models.py`, `config.py`

Implement the Regolo AI analysis agent that takes all scan findings and produces the final security report.

Requirements:
- Use the openai Python SDK with custom base_url (Regolo is OpenAI-compatible):
  client = OpenAI(api_key=config.REGOLO_API_KEY, base_url=config.REGOLO_BASE_URL)

- Function: `analyze(repo_url: str, scan_result: ScanResult) -> str`
  - Returns a markdown security report string
  - Build a prompt that includes:
    - Repo URL and stats (total files scanned, finding counts by severity)
    - All findings formatted as a structured list
    - Ask the AI to: correlate findings, identify attack chains, prioritize remediations
  - The report must contain these sections (exact headings):
    ## Executive Summary
    ## Overall Risk Score  (format: X/10 with brief justification)
    ## Critical & High Findings  (detail each one with impact + fix)
    ## Attack Chains  (how multiple findings could combine into an attack)
    ## Remediation Roadmap  (ordered action list: immediate / this week / this month)
    ## Quick Wins  (fixes under 30 minutes)
  - max_tokens: 4000, temperature: 0.2

- Function: `get_available_models() -> list[str]`
  - Call GET /models on Regolo API, return list of model ids
  - Return fallback list ["gpt-4o", "gpt-4o-mini"] on error
```

---

### TASK B4: `server.py` + `static/index.html`

```
Create TWO files:
- `/Users/ruben/Progetti/estera/CoSentinel/server.py`  (FastAPI backend)
- `/Users/ruben/Progetti/estera/CoSentinel/static/index.html`  (frontend, single file)

Read first: `models.py`, `config.py`, `agent.py`

---

FILE 1: server.py
-----------------
FastAPI app that exposes the scan pipeline as a REST API.

Install: pip3 install fastapi uvicorn python-multipart

Endpoints:

POST /api/scan
  Body (JSON): { "repo_url": str, "github_token": str (optional), "model": str (optional) }
  - Runs the full pipeline sequentially:
    1. fetcher.fetch_repo()
    2. fetcher.list_repo_files()
    3. deps.scan_dependencies()  (parallel with 4 and 5)
    4. secrets.scan_secrets()
    5. code.scan_code()
    6. config_audit.scan_config()
    7. agent.analyze()
  - Returns JSON:
    {
      "report": "<markdown string>",
      "findings": [ { "id", "severity", "category", "title", "description",
                      "file_path", "line_number", "evidence", "fix_suggestion",
                      "auto_fixable", "cve_ids" } ],
      "stats": { "critical": int, "high": int, "medium": int, "low": int, "total_files": int },
      "repo_name": str
    }

GET /api/models
  - Returns JSON: { "models": ["gpt-4o", ...] }
  - Calls agent.get_available_models()

POST /api/create-pr
  Body (JSON): { "repo_url": str, "github_token": str, "finding_ids": list[str] }
  - Calls pr_creator.create_fix_pr()
  - Returns JSON: { "pr_url": str }

GET /
  - Serves static/index.html

Mount static files: app.mount("/static", StaticFiles(directory="static"))
Add CORS middleware for localhost.
Run with: uvicorn server:app --reload --port 8000

---

FILE 2: static/index.html
--------------------------
Single-file frontend. NO build step. Vanilla HTML + CSS + JS only.
Inspired by the Folio design: https://21st.dev/community/templates/folio-open-source-data-intelligence-landing-template

Visual style:
- Font: Inter (Google Fonts CDN)
- LIGHT MODE ONLY — no dark mode, no toggle
- Colors: bg=#ffffff, text=#0a0a0a, accent=#0a0a0a, border=#e5e5e5, muted=#6b7280
- Clean, minimal, lots of whitespace
- Rounded corners: 12px cards, 8px buttons
- Subtle shadows on cards

Layout sections:

[NAVBAR]
- Left: "◈ CoSentinel" wordmark (bold, serif-like)
- Right: "GitHub" link only

[HERO]
- Center-aligned
- Tag pill: "AI-Powered Security · Open Source"
- H1 (large, bold): "Secure Your Code\nBefore It Ships"
- Subtitle: "CoSentinel scans your GitHub repository for vulnerabilities,\nexposed secrets, and misconfigurations — then fixes them."
- Two buttons: [Scan a Repository →] (black/filled) + [View on GitHub] (outlined)
- Below buttons: small text "Supports public & private repos · Powered by Regolo AI"

[SCAN PANEL] (appears below hero, card style)
- Input: "GitHub Repository URL" (full width, large)
- Row: GitHub Token input (password, optional) + Model selector dropdown
- Checkbox: "I confirm this repository is authorized for security scanning"
- Button: "Start Security Scan" (full width, disabled until checkbox)

[PROGRESS] (hidden until scan starts, replaces scan panel)
- Animated progress list, each step:
  ○ Fetching repository
  ○ Scanning dependencies (OSV.dev)
  ○ Detecting secrets
  ○ Auditing source code
  ○ Auditing configuration
  ○ AI Analysis (Regolo)
- Each step: pending (gray) → in-progress (pulsing blue dot) → done (green checkmark)
- Fake streaming: steps animate in sequence during actual API call

[RESULTS] (hidden until scan complete)
- Stats bar: 4 pills — CRITICAL (red) / HIGH (orange) / MEDIUM (yellow) / LOW (blue) — with counts
- Risk score badge: "Risk Score: 8.5/10" (color-coded)
- Repo name + scan timestamp

[FINDINGS TABLE]
- Grouped by severity (CRITICAL first)
- Each finding: expandable card
  - Left: colored severity badge
  - Title + category tag (pill)
  - File path + line number (monospace, small)
  - Collapsed: title only
  - Expanded: description, evidence (dark code block), fix suggestion
  - Green "Auto-fixable" badge if applicable

[FIX PR SECTION]
- Only shown if any auto_fixable findings exist
- Card with: "🔧 X findings can be auto-fixed"
- List of fixable finding titles
- Button: "Create Fix PR on GitHub" → POST /api/create-pr → show PR link

[REPORT SECTION]
- "📄 Full AI Report" card
- Rendered markdown (use marked.js CDN)
- Download button: downloads report as .md file

JS behavior:
- On "Start Scan": POST /api/scan, animate progress steps, populate results on response
- Fetch models on page load from GET /api/models, populate selector
- All API calls to relative URLs (same origin)
- No framework, no bundler — pure fetch() + DOM manipulation
```

---

## ME (main brain — this terminal) will build:
- `pr_creator.py` — GitHub API PR creation
- Integration testing
- Bug fixes coordination

---

## Install dependencies (run in terminal before starting):
```bash
cd /Users/ruben/Progetti/estera/CoSentinel
pip3 install fastapi uvicorn openai requests python-dotenv gitpython python-multipart
```
