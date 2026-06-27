# CoSentinel — AI-Powered Repository Security Scanner

Point it at a GitHub repo and it finds vulnerable dependencies, leaked secrets, dangerous code, and misconfigurations — then explains how to fix them with an AI security report.

## What it does

- **Scans dependencies** against the OSV.dev vulnerability database (PyPI, npm, Maven, Go, RubyGems) and flags known CVEs.
- **Detects leaked secrets** in source code *and git history* — API keys, tokens, private keys — with values redacted, never echoed back.
- **Audits source code** for shell injection, SQL injection, eval/exec, insecure deserialization, XSS, and weak crypto across Python, JS/TS, PHP, Ruby, Go, and Bash.
- **Audits configuration** — Dockerfiles, CI workflows, docker-compose, k8s — then writes an executive AI report with a risk score, attack chains, and a prioritized remediation roadmap.

## How it works

```
        GitHub URL + token
                │
                ▼
        fetcher.fetch_repo ──► clone + list files
                │
   ┌────────────┼────────────┬─────────────┐
   ▼            ▼            ▼             ▼
 deps        secrets        code        config        (parallel scanners)
 (OSV)      (regex)       (patterns)    (audit)
   └────────────┼────────────┴─────────────┘
                ▼
        scan git history (secrets in commits)
                │
                ▼
        agent.analyze ──► Regolo AI security report
                │
                ▼
   server.py  ──SSE──►  static/index.html  (live progress + findings)
                │
                ▼
        pr_creator ──► optional auto-fix PR on GitHub
```

## Tech Stack

| Component        | Technology                              |
|------------------|------------------------------------------|
| Backend API      | FastAPI + Uvicorn (SSE streaming)        |
| Scanners         | Python stdlib + `requests` + ThreadPool  |
| Vulnerability DB | OSV.dev public API                       |
| AI analysis      | Regolo AI (OpenAI-compatible) — `gpt-oss-120b` |
| Frontend         | Vanilla HTML/CSS/JS, `marked.js` (no build) |
| Repo + PRs       | git + GitHub REST API                    |

## Run locally

```bash
pip3 install fastapi uvicorn openai requests python-dotenv gitpython python-multipart
uvicorn server:app --reload --port 8000
open http://localhost:8000
```

## Built at

**RedCarbon Hackathon — AI for Security** · June 27, 2025 · OGR Torino.

## Powered by

[Regolo AI](https://regolo.ai) — running `gpt-oss-120b` for the security analysis and report generation.
