# CoSentinel — CLAUDE CODE Supervisione + Frontend V2

Project: /Users/ruben/Progetti/CoSentinel/
Read AGENTS.md before starting (graphify + ponytail rules).
You are the MAIN AGENT — supervise quality + own the frontend.

Your job: D1 → D2 → D3 → D4 (in order).

---

## D1: Replace polling progress with SSE real-time streaming

The current /api/scan returns after the full pipeline completes (~30-60s).
Users see a fake animated progress. Fix this with Server-Sent Events.

### D1a: Modify server.py — add SSE scan endpoint

Add a new endpoint alongside the existing /api/scan:

```python
from fastapi.responses import StreamingResponse
import asyncio, json

@app.get("/api/scan/stream")
async def scan_stream(repo_url: str, github_token: str = "", model: str = ""):
    """
    SSE endpoint. Client connects via EventSource.
    Streams progress events then the final result.

    Event format (text/event-stream):
      data: {"type": "progress", "step": 1, "label": "Fetching repository..."}\n\n
      data: {"type": "progress", "step": 2, "label": "Scanning dependencies..."}\n\n
      ...
      data: {"type": "result", "report": "...", "findings": [...], "stats": {...}}\n\n
      data: {"type": "error", "message": "..."}\n\n

    Steps:
      1 — Fetching repository
      2 — Scanning dependencies
      3 — Detecting secrets
      4 — Auditing source code
      5 — Auditing configuration files
      6 — Scanning git history
      7 — AI Analysis (Regolo)
    """
    async def generate():
        import sys
        sys.path.insert(0, '.')
        from fetcher import fetch_repo, list_repo_files, cleanup_repo
        from scanners.deps import scan_dependencies
        from scanners.secrets import scan_secrets
        from scanners.code import scan_code
        from scanners.config_audit import scan_config
        from models import ScanResult
        from agent import analyze
        import concurrent.futures

        def emit(data: dict) -> str:
            return f"data: {json.dumps(data)}\n\n"

        local_path = None
        try:
            yield emit({"type": "progress", "step": 1, "label": "Fetching repository..."})
            local_path, repo_name = await asyncio.get_event_loop().run_in_executor(
                None, lambda: fetch_repo(repo_url, github_token)
            )
            all_files = list_repo_files(local_path)

            yield emit({"type": "progress", "step": 2, "label": f"Scanning dependencies ({len(all_files)} files)..."})
            with concurrent.futures.ThreadPoolExecutor() as pool:
                loop = asyncio.get_event_loop()
                dep_fut = loop.run_in_executor(pool, scan_dependencies, local_path)

                yield emit({"type": "progress", "step": 3, "label": "Detecting secrets..."})
                sec_fut = loop.run_in_executor(pool, scan_secrets, local_path, all_files)

                yield emit({"type": "progress", "step": 4, "label": "Auditing source code..."})
                code_fut = loop.run_in_executor(pool, scan_code, local_path, all_files)

                yield emit({"type": "progress", "step": 5, "label": "Auditing configuration files..."})
                cfg_fut = loop.run_in_executor(pool, scan_config, local_path, all_files)

                dep_f, sec_f, code_f, cfg_f = await asyncio.gather(dep_fut, sec_fut, code_fut, cfg_fut)

            try:
                from scanners.git_history import scan_git_history
                yield emit({"type": "progress", "step": 6, "label": "Scanning git history..."})
                git_f = await asyncio.get_event_loop().run_in_executor(None, scan_git_history, local_path)
            except ImportError:
                git_f = []

            all_f = dep_f + sec_f + code_f + cfg_f + git_f
            scan_result = ScanResult(
                repo_url=repo_url, repo_name=repo_name,
                local_path=local_path, findings=all_f
            )

            yield emit({"type": "progress", "step": 7, "label": "AI Analysis with Regolo..."})
            report = await asyncio.get_event_loop().run_in_executor(
                None, lambda: analyze(repo_url, scan_result, model or None)
            )

            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in all_f:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

            findings_json = [
                {
                    "id": f.id, "severity": f.severity.value, "category": f.category,
                    "title": f.title, "description": f.description,
                    "file_path": f.file_path, "line_number": f.line_number,
                    "evidence": f.evidence, "fix_suggestion": f.fix_suggestion,
                    "auto_fixable": f.auto_fixable, "cve_ids": f.cve_ids,
                }
                for f in all_f
            ]

            yield emit({
                "type": "result",
                "report": report,
                "findings": findings_json,
                "stats": {**counts, "total_files": len(all_files)},
                "repo_name": repo_name,
            })

        except Exception as e:
            yield emit({"type": "error", "message": str(e)})
        finally:
            if local_path:
                try:
                    cleanup_repo(local_path)
                except Exception:
                    pass

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
```

Keep the existing POST /api/scan as-is (don't remove it).

---

## D2: Update static/index.html — switch to SSE + improve UX

Open static/index.html and make these changes:

### 2a: Replace fetch POST with EventSource SSE

Replace the "Start Security Scan" click handler:

```javascript
// OLD: fetch POST
// NEW: EventSource SSE

function startScan() {
  const repoUrl = document.getElementById('repo-url').value.trim();
  const token = document.getElementById('github-token').value.trim();
  const model = document.getElementById('model-select').value;

  if (!repoUrl) return;

  // Build SSE URL
  const params = new URLSearchParams({ repo_url: repoUrl });
  if (token) params.set('github_token', token);
  if (model) params.set('model', model);

  showProgress();

  const es = new EventSource(`/api/scan/stream?${params}`);

  es.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === 'progress') {
      updateProgressStep(data.step, data.label);
    }
    else if (data.type === 'result') {
      es.close();
      hideProgress();
      showResults(data);
    }
    else if (data.type === 'error') {
      es.close();
      hideProgress();
      showError(data.message);
    }
  };

  es.onerror = () => {
    es.close();
    hideProgress();
    showError('Connection lost. Please try again.');
  };
}
```

### 2b: Progress steps now show REAL labels from SSE

Each progress event has `step` (1-7) and `label` (real status from backend).
Update the step element text dynamically when the event arrives.
Steps 1-6 complete (green ✓) when the next step event arrives.
Step 7 completes when type=result arrives.

### 2c: Add findings count badge to navbar when scan completes

After results load, show in navbar (top right, next to GitHub link):
```
● 47 findings  (red dot if any CRITICAL/HIGH, yellow if MEDIUM, green if LOW only)
```

### 2d: Add "Copy Report" button next to "Download Report"

```javascript
document.getElementById('copy-report').onclick = () => {
  navigator.clipboard.writeText(currentReport);
  // Show "Copied!" for 2 seconds then revert label
};
```

### 2e: Improve finding cards

Each finding card (in the <details> expansion) should show:
- File path as a monospace pill that user can click to copy path to clipboard
- If cve_ids not empty: show CVE badges linking to https://nvd.nist.gov/vuln/detail/{cve}
- Fix suggestion: if it contains a code block (backtick-wrapped), render as <code>

---

## D3: Quality review of all Builder A + B output

Read these files fully and check for issues:
- fetcher.py
- scanners/deps.py
- scanners/secrets.py
- scanners/code.py
- scanners/config_audit.py
- agent.py
- server.py

For each file, check:
1. Does it import from models correctly? (from models import Finding, Severity)
2. Does it handle exceptions without crashing the pipeline?
3. Are Finding IDs unique (thread-safe counter with Lock)?
4. Does it respect config.SKIP_EXTENSIONS and config.MAX_FILE_SIZE?
5. Is evidence ever leaking full secrets? (Must be redacted)

Fix any issues found directly. Report what you fixed.

---

## D4: Create README.md for judges

Create /Users/ruben/Progetti/CoSentinel/README.md

Content:
- Title: "# CoSentinel — AI-Powered Repository Security Scanner"
- Tagline: 1 sentence
- Section: ## What it does (4 bullet points, concrete)
- Section: ## How it works (the pipeline as ASCII diagram)
- Section: ## Tech Stack (table: component → technology)
- Section: ## Run locally (3 commands: pip install, uvicorn, open browser)
- Section: ## Built at (RedCarbon Hackathon, AI for Security, June 27 2025, OGR Torino)
- Section: ## Powered by (Regolo AI — gpt-oss-120b)

Keep it short. Judges read fast.

---

## What Claude Code owns
- static/index.html (UX + SSE)
- server.py SSE endpoint (D1)
- Code quality review of all modules (D3)
- README.md for judges (D4)

Do NOT touch: models.py, config.py, fetcher.py, scanners/deps.py, scanners/secrets.py
(Those are Codex territory)
