# CoSentinel — Attack Surface Mapper for GitHub Repos

Point CoSentinel at a GitHub repository. It finds vulnerabilities, leaked secrets, weak auth, exposed routes, and misconfigurations — then **maps plausible entry paths** (inferred vs live-confirmed) and generates an executive AI remediation report.

Built for **RedCarbon Hackathon — AI for Security** · OGR Torino.

## What it does

| Layer | Capability |
|-------|------------|
| **Static scan** | Dependencies, secrets, code, routes, auth, config, GitHub Actions, Semgrep (optional), container, git history |
| **Passive OSINT** | crt.sh subdomains + Wayback Machine archived paths (from deploy targets) |
| **Attack graph** | Correlates findings into entry points (`INFERRED`; live `CONFIRMED` only when explicitly enabled) |
| **Live validation** | **Disabled by default** (`ENABLE_LIVE_SCAN=false`) — nmap, nuclei, nikto/gobuster when enabled locally |
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
| `trivy` | Dockerfile misconfigs + unpinned/vulnerable base images (needs `trivy` in PATH for full scan) |
| `github_actions` | CI/CD poison patterns (`pull_request_target`, script injection, curl\|bash) |
| `semgrep` | SAST via `semgrep --config p/ci` (optional CLI) |
| `crtsh` | Passive subdomain discovery from Certificate Transparency logs |
| `wayback` | Archived sensitive URLs from Internet Archive CDX (passive OSINT) |
| `git_history` | Secrets still present in commit history |
| `network` | Live entry-point validation (**off by default** — set `ENABLE_LIVE_SCAN=true` locally) |

## How it works

```
GitHub URL (+ optional live target)
        │
        ▼
   clone repo ──► 11 parallel static scanners
        │
        ▼
   git history ──► crt.sh + Wayback enrichment (from deploy targets)
        │
        ▼
   optional live validation (ENABLE_LIVE_SCAN=true only)
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
# ENABLE_LIVE_SCAN=false   # keep false for hackathon/public demos

uvicorn server:app --reload --port 8000
open http://localhost:8000
```

### Live validation (local demo only)

**Disabled by default** so the platform is safe to demo without handing strangers a live scanner.

```bash
# .env — only on your machine, never on a public deployment
ENABLE_LIVE_SCAN=true
```

Then optionally set **Live target** in the UI (hidden when disabled).

### Optional CLI tools

```bash
brew install trivy nuclei semgrep
```

Trivy, nuclei, and semgrep skip gracefully if not installed. crt.sh and Wayback use HTTPS only.

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
| Live checks | nmap, curl, openssl, dig, nuclei, nikto, gobuster (optional, if installed) |

### Optional CLI tools

```bash
brew install trivy nuclei   # container base CVEs + live misconfig templates
```

Trivy and nuclei are skipped gracefully if not installed. crt.sh uses HTTPS only (no extra install).

## Tests

```bash
python3 -m unittest discover -s tests -q
```

## Demo flow (3 minutes)

**Local demo repo** (no GitHub, no live probe):

```bash
brew install trivy semgrep   # once
python3 scripts/run_demo_scan.py
```

Or in the UI paste:

`file:///Users/ruben/Progetti/CoSentinel/demo/cosentinel-vuln-demo`

See [demo/DEMO.md](demo/DEMO.md) for full setup.

1. Scan demo repo → **EP: Container risk on publicly exposed deployment (INFERRED)**
2. README deploy URLs → crt.sh sensitive subdomains → **EP: Expanded subdomain attack surface**
3. `pull_request_target` workflow → **EP: CI/CD supply-chain risk**
4. AI report with inferred entry points (live scan stays disabled)

## Ethics & scope

CoSentinel is an **attack surface mapper**, not an exploit framework. Passive OSINT (crt.sh, Wayback) never probes live hosts. Live checks are off by default and must stay disabled on any public deployment.

## Powered by

[Regolo AI](https://regolo.ai) — security analysis and report generation.
