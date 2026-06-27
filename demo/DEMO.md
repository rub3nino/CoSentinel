# Local hackathon demo

## 1. One-time setup

```bash
# CLI scanners (optional but recommended)
brew install trivy semgrep

# Init demo git repo (required for file:// scans)
cd demo/cosentinel-vuln-demo
git init
git add -A
git commit -m "hackathon vuln demo"
cd ../..

# .env — keep live scan OFF for public demos
# ENABLE_LIVE_SCAN=false
```

## 2. Run scan (CLI)

```bash
python3 scripts/run_demo_scan.py
```

Outputs entry points + saves `demo/last_demo_scan.json` and `demo/last_demo_report.md`.

## 3. Run scan (UI)

```bash
uvicorn server:app --port 8000
```

Paste in **Repository URL**:

```
file:///Users/ruben/Progetti/CoSentinel/demo/cosentinel-vuln-demo
```

(Adjust path to your machine.)

## Expected entry points (INFERRED)

| Trigger | Entry point |
|---------|-------------|
| `docker-compose` `0.0.0.0` + `FROM python:latest` | Container risk on publicly exposed deployment |
| README deploy URL `tiivo.it` | crt.sh + Wayback subdomain / archived paths |
| `.github/workflows` `pull_request_target` | CI/CD supply-chain risk |

Live target field is **hidden** when `ENABLE_LIVE_SCAN=false` (default).
