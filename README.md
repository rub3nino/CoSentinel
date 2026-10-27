<p align="center">
  <img src="assets/logo/cosentinel-logo.svg" alt="Cosentinel" width="120">
</p>

<h1 align="center">Cosentinel</h1>

<p align="center">
  A local, SSH-based security-posture &amp; hardening orchestrator for your own machines.
</p>

---

Cosentinel runs **on your laptop**, connects to the machines **you own** over SSH, and
orchestrates established security scanners in one place:

- **Lynis** — host hardening audit, from *inside* the machine.
- **Nmap** — network surface, seen from *outside*.
- **Nuclei** — known-vulnerability detection against exposed services.

It normalizes everything into a single **finding** model, keeps history in a local
SQLite file, and can render a static, read-only HTML report. There is **no always-on
service and nothing exposed to the internet** — the whole state is one folder you control.

> Cosentinel does not reinvent scanners. Its value is **orchestration, normalization,
> correlation and history** across tools that otherwise live in separate silos.

## Why it is safe to run

Three ideas are built into the core, not bolted on:

1. **Scope allowlist.** A machine that is not in your config *cannot* be scanned.
2. **Intensity tiers.** `passive → safe → aggressive → exploit`. v1 ships **detection
   only** (max `safe`). Aggressive needs an explicit `--confirm`; exploit additionally
   requires the target to be marked `lab: true`.
3. **Audit log.** Every authorized (or refused) action is written to an append-only log.

Use it only on systems you own or are explicitly authorized to test.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Optional scanners (install the ones you want; adapters skip gracefully if missing):

```bash
brew install nmap nuclei          # macOS
# Lynis runs on the *target*; install it there (apt install lynis, etc.)
```

## Quick start

```bash
cosentinel init                 # create cosentinel.yaml (your allowlist) + .cosentinel/
cosentinel targets              # show the allowlist
cosentinel adapters             # which scanners are available on this host
cosentinel scan localhost --dry-run   # see the EXACT commands, run nothing
cosentinel scan localhost       # run the 'full' profile (SAFE)
cosentinel report localhost -o report.html   # static HTML report
cosentinel diff localhost       # what changed since the previous scan
cosentinel history              # past scans
```

Add a remote host to `cosentinel.yaml` (it reuses your `~/.ssh/config`, keys and agent):

```yaml
targets:
  - id: homeserver
    host: homeserver     # ssh alias or IP
    ssh: true
    sudo: true           # Lynis needs root to read system config
    url: http://homeserver
```

## Profiles

| Profile   | Intensity | Scanners              | What it does |
|-----------|-----------|-----------------------|--------------|
| `audit`   | safe      | lynis                 | Hardening audit from inside |
| `network` | safe      | nmap                  | Network surface from outside |
| `vuln`    | safe      | nuclei                | Known-vulnerability detection |
| `full`    | safe      | lynis + nmap + nuclei | Everything in v1 |

## Status

**v1 — detection only** (Lynis + Nmap + Nuclei). The architecture is designed so more
scanners (OpenVAS, testssl, ZAP) and, later, gated exploitation tooling slot in as new
adapters without touching the rest. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```
