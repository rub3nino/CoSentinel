# CoSentinel — Prompt per CLAUDE CODE (Builder B)

Incolla questo prompt intero nel secondo terminale Claude Code per iniziare.

---

## PROMPT DA INCOLLARE IN CLAUDE CODE

```
You are Builder B for CoSentinel, an AI-powered GitHub repository security scanner.
Project path: /Users/ruben/Progetti/CoSentinel/

Read AGENTS.md first for coding standards (graphify knowledge graph + ponytail lazy-dev rules).
Read models.py and config.py — these are the shared data contracts. Do NOT modify them.

Your job: implement 4 modules. Build them in order B1 → B2 → B3 → B4.
After each file, confirm it is written and move to the next immediately.

---

### B1: scanners/code.py

Create /Users/ruben/Progetti/CoSentinel/scanners/code.py

Scans source code files for dangerous security patterns.

```python
from models import Finding, Severity

def scan_code(local_path: str, all_files: list[str]) -> list[Finding]:
    """
    For each file in all_files:
      1. Detect language by extension:
         .py → "python"
         .js .ts .jsx .tsx .mjs → "javascript"
         anything else → "generic"

      2. Apply patterns from config.CODE_PATTERNS[language] + config.CODE_PATTERNS["generic"]
         Each pattern: name -> regex string

      3. Scan file line by line with re.search(pattern, line)

      4. For each match, create Finding:
         id = f"CODE-{counter:03d}"
         severity mapping:
           CRITICAL → "Shell Injection", "SQL Concatenation", "Eval Usage", "Pickle Deserialization"
           HIGH     → "innerHTML XSS", "document.write", "Child Process Shell", "Exec Usage"
           MEDIUM   → "Debug Mode", "Hardcoded Bind All", "Assert Auth"
           LOW      → "TODO Security", "Hardcoded IP"
         category = "code"
         title = pattern_name
         description = explain_risk(pattern_name)  — write a dict mapping name→explanation
         file_path = relative path from local_path
         line_number = line number (1-indexed)
         evidence = line.strip()[:200]
         fix_suggestion = fix_for(pattern_name)  — write a dict mapping name→fix
         auto_fixable = False

    Use ThreadPoolExecutor(max_workers=8) for parallel file scanning.
    Use threading.Lock() for the counter.
    """

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
    "TODO Security": "Security-related TODO/FIXME indicates known unresolved security issue",
    "Hardcoded IP": "Hardcoded internal IP addresses reveal network topology",
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
    "TODO Security": "Resolve the security issue before deploying to production",
    "Hardcoded IP": "Move to configuration file or environment variable",
}
```

---

### B2: scanners/config_audit.py

Create /Users/ruben/Progetti/CoSentinel/scanners/config_audit.py

Audits configuration files for security misconfigurations.

```python
from models import Finding, Severity

def scan_config(local_path: str, all_files: list[str]) -> list[Finding]:
    """
    Filter all_files to only config files matching these patterns:
    - filename == "Dockerfile" or starts with "Dockerfile."
    - path contains ".github/workflows/" and ends in .yml or .yaml
    - filename in [".env.example", ".env.sample", ".env.test"]
    - filename in ["docker-compose.yml", "docker-compose.yaml"]
    - filename in ["nginx.conf", "apache2.conf", "httpd.conf"]
    - path contains "k8s/" or "kubernetes/" or "helm/" and ends in .yaml

    For each config file:
    1. Detect config type by filename/path
    2. Apply patterns from config.DANGEROUS_CONFIG_PATTERNS for known types
    3. For docker-compose.yml: also check line by line for:
       - "privileged: true"
       - ports that expose 0.0.0.0 (e.g. "0.0.0.0:22:22")
    4. For each match:
       id = f"CFG-{counter:03d}"
       severity:
         HIGH   → secrets in ENV, privileged mode, exposed sensitive ports
         MEDIUM → latest tag in Dockerfile, pull-requests: write in CI
         LOW    → best-practice issues
       category = "config"
       title = f"{config_type}: {pattern_name}"
       description = context-specific explanation
       file_path = relative path
       line_number = matching line number
       evidence = matching line stripped
       fix_suggestion = specific fix for that config type
       auto_fixable = False
    """
```

---

### B3: agent.py

Create /Users/ruben/Progetti/CoSentinel/agent.py

Regolo AI analysis agent — takes all scan findings, produces security report.

```python
import os
from openai import OpenAI
import config
from models import ScanResult, Severity

client = OpenAI(
    api_key=config.REGOLO_API_KEY,
    base_url=config.REGOLO_BASE_URL,
)

def get_available_models() -> list[str]:
    """
    Try: client.models.list() → return [m.id for m in response]
    On any error: return ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"]
    """

def analyze(repo_url: str, scan_result: ScanResult, model: str = None) -> str:
    """
    Build a structured prompt with:
    - Repo URL
    - Stats: total files, findings by severity count
    - All findings formatted as:
      [{id}] {severity} | {category} | {title}
      File: {file_path}:{line_number}
      Evidence: {evidence}
      Fix: {fix_suggestion}
      ---

    System prompt:
      "You are a senior security engineer writing an executive security assessment.
       Be specific. Quote evidence. Prioritize by real-world exploitability, not just CVSS.
       Identify attack chains where multiple findings combine."

    User prompt asks for this EXACT markdown structure:
      ## Executive Summary
      ## Overall Risk Score
      (format: X.X/10 — one sentence justification)
      ## Critical & High Findings
      (each: ### [ID] Title, Impact, Evidence quoted, Exact fix command or code)
      ## Attack Chains
      (how findings combine: e.g. exposed secret + debug mode = full system compromise)
      ## Remediation Roadmap
      ### Immediate (today)
      ### This Week
      ### This Month
      ## Quick Wins
      (fixes under 30 minutes, ordered by impact)

    Call: client.chat.completions.create(
        model=model or config.REGOLO_MODEL,
        messages=[{"role": "system", ...}, {"role": "user", ...}],
        temperature=0.2,
        max_tokens=4000,
    )
    Return response.choices[0].message.content
    """
```

---

### B4: server.py + static/index.html

#### server.py

Create /Users/ruben/Progetti/CoSentinel/server.py

FastAPI backend that runs the full scan pipeline.

```python
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio, os
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="CoSentinel")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    repo_url: str
    github_token: str = ""
    model: str = ""

class PRRequest(BaseModel):
    repo_url: str
    github_token: str
    finding_ids: list[str]

@app.get("/")
async def root():
    # serve static/index.html
    from fastapi.responses import FileResponse
    return FileResponse("static/index.html")

@app.get("/api/models")
async def get_models():
    from agent import get_available_models
    return {"models": get_available_models()}

@app.post("/api/scan")
async def scan(req: ScanRequest):
    """
    Run full pipeline:
    1. import and call fetcher.fetch_repo(req.repo_url, req.github_token)
    2. call fetcher.list_repo_files(local_path)
    3. Run in parallel with asyncio.gather (use loop.run_in_executor):
       - deps.scan_dependencies(local_path)
       - secrets.scan_secrets(local_path, all_files)
       - code.scan_code(local_path, all_files)
       - config_audit.scan_config(local_path, all_files)
    4. Combine all findings into ScanResult
    5. Call agent.analyze(repo_url, scan_result, req.model)
    6. Return JSON with report, findings (serialized), stats, repo_name

    On any error: raise HTTPException(status_code=500, detail=str(e))
    Always call fetcher.cleanup_repo() in a finally block.
    """

@app.post("/api/create-pr")
async def create_pr(req: PRRequest):
    from pr_creator import create_fix_pr
    pr_url = create_fix_pr(req.repo_url, req.github_token, req.finding_ids)
    return {"pr_url": pr_url}
```

Run with: `uvicorn server:app --reload --port 8000`

#### static/index.html

Create /Users/ruben/Progetti/CoSentinel/static/index.html

Single-file frontend. NO build step. Pure HTML + CSS + JS only.
CDN dependencies (add in <head>):
- Inter font: https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap
- marked.js: https://cdn.jsdelivr.net/npm/marked/marked.min.js

DESIGN SPEC — LIGHT MODE ONLY — inspired by Folio (https://21st.dev/community/templates/folio):
- Font: Inter throughout
- bg: #ffffff, text: #0a0a0a, muted: #6b7280, border: #e5e5e5
- accent button: bg #0a0a0a, text #ffffff, hover bg #333
- Cards: border 1px #e5e5e5, border-radius 12px, padding 24px
- Max content width: 1100px, centered
- Severity colors: CRITICAL #dc2626, HIGH #ea580c, MEDIUM #ca8a04, LOW #2563eb, INFO #6b7280

LAYOUT:

[NAVBAR] — sticky top, border-bottom 1px #e5e5e5
  Left: "◈ CoSentinel" (font-weight 700, font-size 18px)
  Right: <a href="https://github.com">GitHub</a> (muted, no decoration)

[HERO] — padding 80px 24px, text-align center
  Pill: "AI-Powered Security · Open Source"
        border 1px #e5e5e5, border-radius 999px, padding 6px 16px, font-size 13px, color #6b7280
  H1: "Secure Your Code" (font-size 56px, font-weight 700, line-height 1.1)
      "Before It Ships"  (same, second line)
  Subtitle: "CoSentinel scans your GitHub repository for vulnerabilities, exposed secrets,"
            "and misconfigurations — then shows you exactly how to fix them."
            (color #6b7280, font-size 18px, max-width 560px, margin: 0 auto)

[SCAN CARD] — card style, max-width 680px, margin: 0 auto 48px

  Input: GitHub Repository URL
    placeholder: "https://github.com/owner/repo"
    full width, height 48px, border 1px #e5e5e5, border-radius 8px, padding 0 16px, font-size 15px

  Row (gap 12px):
    Input: GitHub Token (password type, optional — for private repos)
      placeholder: "ghp_... (optional, for private repos)"
      flex 1
    Select: Model — populated via GET /api/models on page load
      flex 0 0 160px

  Checkbox row:
    <input type="checkbox" id="auth">
    <label for="auth">I confirm this repository is authorized for security testing</label>

  Button: "Start Security Scan →"
    full width, height 48px, bg #0a0a0a, color #fff, border-radius 8px, font-size 15px, font-weight 500
    disabled (opacity 0.4, cursor not-allowed) until checkbox checked

[PROGRESS SECTION] — hidden initially, shown when scan starts
  Card with title "Scanning repository..."
  6 steps as a vertical list:
    Each step: circle indicator + label
    States: pending (gray circle) → active (pulsing blue dot, CSS animation) → done (green ✓)
  Steps:
    1. "Fetching repository"
    2. "Scanning dependencies (OSV.dev)"
    3. "Detecting secrets"
    4. "Auditing source code"
    5. "Auditing configuration files"
    6. "AI Analysis (Regolo)"
  Animate steps sequentially with setTimeout during the API call.
  Steps 1-5 animate at equal intervals, step 6 stays active until API responds.

[RESULTS SECTION] — hidden until scan complete

  Stats bar (4 pills inline):
    CRITICAL (n) — bg #fef2f2, color #dc2626, border #fecaca
    HIGH (n)     — bg #fff7ed, color #ea580c, border #fed7aa
    MEDIUM (n)   — bg #fefce8, color #ca8a04, border #fef08a
    LOW (n)      — bg #eff6ff, color #2563eb, border #bfdbfe

  Risk Score banner:
    "Risk Score: X.X / 10" — large, centered, color based on score:
    >=8: #dc2626, >=6: #ea580c, >=4: #ca8a04, else #16a34a

  Repo name + timestamp small text

[FINDINGS LIST]
  Grouped by severity (CRITICAL → HIGH → MEDIUM → LOW)
  Section header per severity group: "● CRITICAL FINDINGS (n)"
  Each finding = expandable card (<details><summary>):
    Summary row:
      Severity badge (colored pill)
      Category tag (gray pill): "dependency" / "secret" / "code" / "config"
      Title (font-weight 500)
      File path:line (monospace, color #6b7280, font-size 13px)
      Right: "Auto-fixable ✓" (green, small) if auto_fixable
    Expanded content:
      Description paragraph
      Evidence: <pre><code> dark block (#1a1a1a bg, #f8f8f2 text, border-radius 8px, padding 12px)
      Fix suggestion: formatted text with any code in <code> tags
      CVE IDs if present: clickable links to https://nvd.nist.gov/vuln/detail/{cve}

[PR SECTION] — only shown if any auto_fixable findings
  Card: "🔧 Auto-Fix Available"
  List of fixable finding titles with checkboxes (all pre-checked)
  Button: "Create Fix PR on GitHub"
    On click → POST /api/create-pr with checked finding ids
    Show spinner → show PR URL as clickable link on success
    Requires GitHub token to be filled

[AI REPORT SECTION]
  Title: "Full AI Security Report"
  Rendered markdown (use marked.parse(reportText), insert into div)
  Styled: h2 border-bottom, code blocks dark bg, lists indented
  Download button: "⬇ Download Report (.md)"
    Creates blob URL, triggers download

JS BEHAVIOR:
  On page load:
    - fetch("/api/models") → populate select
  On "Start Security Scan" click:
    - Hide scan card, show progress section
    - Start step animation (setTimeout intervals ~800ms per step, steps 1-5)
    - POST /api/scan with {repo_url, github_token, model}
    - On response: complete step 6, hide progress, show results
    - Populate stats, risk score, findings, report
    - On error: show error card with error message, re-show scan card

All state in JS variables (no framework). No external JS libraries except marked.js.
```

When all 4 files are written, test:
```bash
cd /Users/ruben/Progetti/CoSentinel
pip3 install fastapi uvicorn python-multipart
python3 -c "from scanners.code import scan_code; print('code OK')"
python3 -c "from scanners.config_audit import scan_config; print('config OK')"
python3 -c "from agent import get_available_models; print(get_available_models())"
python3 -c "import server; print('server OK')"
```
Report any errors back.
```

---

## Architettura CoSentinel — Riferimento Rapido per Claude Code

```
CoSentinel/
├── models.py          ← DATA CONTRACTS (non modificare)
│   ├── Finding        ← ogni vulnerabilità trovata
│   │   ├── id: str                  "CODE-001", "CFG-003"
│   │   ├── severity: Severity       CRITICAL/HIGH/MEDIUM/LOW/INFO
│   │   ├── category: str            "dependency"/"secret"/"code"/"config"
│   │   ├── title: str
│   │   ├── description: str
│   │   ├── file_path: str|None      path relativo alla root del repo
│   │   ├── line_number: int|None
│   │   ├── evidence: str            snippet (mai secret completo)
│   │   ├── cve_ids: list[str]
│   │   ├── fix_suggestion: str
│   │   ├── auto_fixable: bool
│   │   └── fix_patch: str|None
│   └── ScanResult
│       ├── repo_url, repo_name, local_path: str
│       ├── findings: list[Finding]
│       └── scan_errors: list[str]
│
├── config.py          ← COSTANTI (non modificare)
│   ├── REGOLO_API_KEY = "sk-WC0Sy_z4bf2S8vgWU47KTw"
│   ├── REGOLO_BASE_URL = "https://api.regolo.ai/v1"
│   ├── REGOLO_MODEL = "gpt-4o"
│   ├── CODE_PATTERNS   dict{lang: dict{name: regex}}
│   │   langs: "python", "javascript", "generic"
│   ├── DANGEROUS_CONFIG_PATTERNS  dict{filename: dict{name: regex}}
│   │   keys: "Dockerfile", ".github/workflows", ".env.example"
│   └── SKIP_EXTENSIONS, MAX_FILE_SIZE
│
├── scanners/
│   ├── code.py        ← TUO TASK B1
│   │   └── scan_code(local_path, all_files) -> list[Finding]
│   │       usa config.CODE_PATTERNS, ThreadPoolExecutor
│   │
│   └── config_audit.py ← TUO TASK B2
│       └── scan_config(local_path, all_files) -> list[Finding]
│           usa config.DANGEROUS_CONFIG_PATTERNS
│
├── agent.py           ← TUO TASK B3
│   ├── get_available_models() -> list[str]
│   └── analyze(repo_url, scan_result, model) -> str (markdown)
│       usa OpenAI client con base_url=config.REGOLO_BASE_URL
│
└── server.py          ← TUO TASK B4a
    + static/index.html ← TUO TASK B4b (Folio-style, light only)
```

## Pipeline completa (contesto)

```
GitHub URL + token
      ↓
fetcher.fetch_repo()          ← Builder A
      ↓
fetcher.list_repo_files()     ← Builder A
      ↓ (parallelo con asyncio)
deps.scan_dependencies()      ← Builder A
secrets.scan_secrets()        ← Builder A
code.scan_code()              ← TUO CODICE
config_audit.scan_config()    ← TUO CODICE
      ↓
agent.analyze()               ← TUO CODICE (Regolo AI)
      ↓
server.py POST /api/scan      ← TUO CODICE (orchestration)
static/index.html             ← TUO CODICE (UI)
      ↓
pr_creator.py                 ← Main brain
```

## Regole di codice (AGENTS.md)

1. **Non modificare** `models.py` e `config.py`
2. **Ponytail**: scrivi il minimo. Stdlib > dipendenza. No astrazione non richiesta.
3. **Regolo AI** è OpenAI-compatible: usa `openai.OpenAI(base_url=config.REGOLO_BASE_URL)`
4. **Import obbligatori scanner**: `from models import Finding, Severity` + `import config`
5. **Thread safety**: `threading.Lock()` per counter id (CODE-001, CFG-002...)
6. **FastAPI run**: `uvicorn server:app --reload --port 8000`
7. **index.html**: ZERO framework JS, ZERO build step, marked.js CDN per markdown
