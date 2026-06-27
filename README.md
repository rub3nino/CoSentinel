# CoSentinel — Attack Surface Mapper for GitHub Repos

Point CoSentinel at a GitHub repository. It finds vulnerabilities, leaked secrets, weak auth, exposed routes, and misconfigurations — then **maps plausible entry paths** (inferred vs live-confirmed) and generates an executive AI remediation report.

Built for **RedCarbon Hackathon — AI for Security** · OGR Torino.

## What it does

| Layer | Capability |
|-------|------------|
| **Static scan** | Dependencies (OSV.dev), secrets, code patterns, routes, auth weaknesses, config, exposure inventory, git history |
| **Attack graph** | Correlates findings into entry points (`INFERRED` from repo, `CONFIRMED` after live validation) |
| **Live validation** | Optional authorized target check: nmap, HTTP headers, TLS, DNS, nikto/gobuster |
| **AI report** | Regolo AI — risk score, attack chains, inferred vs confirmed entry points, remediation roadmap |
| **Auto-fix** | GitHub PR with unified-diff patches for safe, mechanical fixes |

## Scanners

| Scanner | Finds |
|---------|--------|
| `deps` | CVEs in PyPI, npm, Maven, Go, RubyGems |
| `secrets` | API keys, tokens, private keys (redacted output) |
| `code` | Shell/SQL injection, eval, XSS, debug mode, weak patterns |
| `routes` | Sensitive endpoints (`/admin`, `/debug`, …) without obvious auth guard |
| `targets` | Deploy URLs/domains declared in README, CI, compose, env samples |
| `auth` | JWT verify disabled, CORS `*`, default secrets, CSRF disabled |
| `exposure` | Public binds, published ports, k8s LoadBalancer/NodePort |
| `config` | Dockerfile, CI, docker-compose, k8s hardening issues |
| `git_history` | Secrets still present in commit history |
| `network` | Live entry-point validation (optional, authorized targets only) |

## How it works

```
GitHub URL (+ optional live target)
        │
        ▼
   clone repo ──► 8 parallel static scanners
        │
        ▼
   git history scan
        │
        ▼
   optional live validation (nmap, headers, TLS, nikto/gobuster)
        │
        ▼
   attack_graph.build_entry_points() ──► INFERRED / CONFIRMED paths
        │
        ▼
   Regolo AI report (SSE live progress in UI)
        │
        ▼
   optional auto-fix PR on GitHub
```

## Quick start

```bash
pip3 install fastapi uvicorn openai requests python-dotenv gitpython python-multipart

# .env
# REGOLO_API_KEY=...
# REGOLO_BASE_URL=https://api.regolo.ai/v1
# REGOLO_MODEL=gpt-oss-120b

uvicorn server:app --reload --port 8000
open http://localhost:8000
```

### Optional live validation

Only on systems you own or are explicitly authorized to test.

1. Paste a GitHub repo URL
2. Optionally set **Live target** (e.g. `scanme.nmap.org` or your staging URL)
3. Confirm authorization checkboxes
4. Run scan — entry points marked **CONFIRMED** when live checks support the inference

Suggested deploy targets from the repo appear as clickable chips under the live target field.

## API

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web UI |
| `GET /api/health` | Status + scanner list |
| `GET /api/scan/stream?repo_url=…&live_target=…` | SSE scan with progress |
| `POST /api/scan` | Full scan (JSON) |
| `GET /api/scans` | Scan history |
| `POST /api/create-pr` | Open fix PR on GitHub |

## Tech stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI + Uvicorn (SSE) |
| Scanners | Python stdlib + `requests` + ThreadPoolExecutor |
| CVE data | [OSV.dev](https://osv.dev) |
| AI | [Regolo AI](https://regolo.ai) — OpenAI-compatible API |
| Frontend | Vanilla HTML/CSS/JS + `marked.js` (no build step) |
| Live checks | nmap, curl, openssl, dig, nikto, gobuster (optional, if installed) |

## Tests

```bash
python3 -m unittest discover -s tests -q
```

## Demo flow (3 minutes)

1. Scan a repo with `docker-compose` exposing `0.0.0.0:8080` + `debug=True` → **EP: Public debug surface (INFERRED)**
2. Add live target `scanme.nmap.org` → network findings → some paths become **CONFIRMED**
3. Show AI report section *Inferred vs Confirmed Entry Points*
4. Click **Create Fix PR** for auto-fixable findings

## Ethics & scope

CoSentinel is an **attack surface mapper**, not an exploit framework. Live checks are passive/light (no CVE auto-exploit, no credential stuffing). Always scan only repositories and hosts you are authorized to test.

## Powered by

[Regolo AI](https://regolo.ai) — security analysis and report generation.
