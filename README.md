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
- **testssl.sh** — TLS / certificate posture of an exposed service, from *outside*.
- **Nikto** — web-server misconfigurations and dangerous files, from *outside*.
- **OpenVAS / Greenbone** — deep vulnerability scan via a running GVM instance (opt-in).
- **ffuf** — content & endpoint discovery (hidden paths, backups, `.git`/`.env`). *Active.*
- **sqlmap** — SQL-injection detection, and lab-only proof of impact. *Active.*
- **OWASP ZAP** — full active web-application scan (SQLi, XSS, traversal, …). *Active.*

It normalizes everything into a single **finding** model, keeps history in a local
SQLite file, and can render a static, read-only HTML report. There is **no always-on
service and nothing exposed to the internet** — the whole state is one folder you control.

> Cosentinel does not reinvent scanners. Its value is **orchestration, normalization,
> correlation and history** across tools that otherwise live in separate silos.

`cosentinel risks` is where that pays off: findings are grouped by asset (mostly the
port) and scored, so a weak SSH config (Lynis) on a port that is **also open** (Nmap)
and carries a **CVE** (Nuclei) surfaces as one high-priority risk — reachable *and* weak
*and* corroborated — instead of three unrelated lines.

## Why it is safe to run

Three ideas are built into the core, not bolted on:

1. **Scope allowlist.** A machine that is not in your config *cannot* be scanned.
2. **Intensity tiers.** `passive → safe → aggressive → exploit`. The default profiles
   are **detection only** (`safe`). The active profiles (`pentest`, `exploit`) send real
   payloads the way a human tester does and are gated: aggressive needs an explicit
   `--confirm`; exploit additionally requires the target to be marked `lab: true`.
   A profile's intensity is a *ceiling* — each tool runs only as hard as it is allowed,
   and the heavy tools (sqlmap/ZAP/ffuf) never fire in a `safe` scan at all.
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
cosentinel risks localhost      # correlated, prioritized risks (not raw findings)
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
| `tls`     | safe      | testssl               | TLS/certificate posture |
| `web`     | safe      | nikto                 | Web-server misconfigurations |
| `full`    | safe      | lynis + nmap + nuclei + testssl + nikto | Everything available |
| `openvas` | safe      | openvas               | Deep GVM scan (needs a running Greenbone) |
| `pentest` | aggressive | lynis + nmap + nuclei + testssl + nikto + ffuf + sqlmap + zap | Active testing like a human attacker. **Needs `--confirm`.** |
| `exploit` | exploit   | nmap + nuclei + testssl + nikto + sqlmap + zap | Prove impact, not just presence. **Needs `--confirm` + `lab: true`.** |

> The `safe` profiles run with no extra ceremony. `pentest` sends real payloads
> (SQL injection, XSS, fuzzing, path brute-forcing) and requires `--confirm`.
> `exploit` additionally proves impact (e.g. sqlmap reaching the DBMS) and only
> runs against a target you have explicitly marked `lab: true`.

```bash
cosentinel scan e0 -p pentest --confirm        # active test of a host you own
cosentinel scan e0 -p pentest --confirm --dry-run   # see exactly what WOULD run first
```

**ffuf wordlist:** point `COSENTINEL_WORDLIST` at a wordlist, or install one
(SecLists/dirb); a small starter list ships in `wordlists/common-web.txt`.

**Running ZAP natively (for Tailscale / host-only targets):** ZAP's packaged
`zap-full-scan.py` only ships in its Docker image, and a Docker container can't
reach a Tailscale IP. To run ZAP against such a target, install ZAP natively and
point the adapter at the bundled shim, which drives `zap.sh` in quick-scan mode:

```bash
# one-time: install a JDK 17+ and ZAP (the Homebrew cask is currently disabled,
# so fetch ZAP's Cross-Platform package from the official release), then:
export COSENTINEL_ZAP="$PWD/scripts/zap-native.sh"   # or symlink it somewhere on PATH
cosentinel scan e0 -p pentest --confirm
```

The shim finds `openjdk` and `zap.sh` automatically (override with `JAVA_HOME` /
`ZAP_SH`). The `COSENTINEL_ZAP` override also accepts a full command, e.g. a
`docker … zap-full-scan.py` invocation, exactly like `GVM_CLI` for OpenVAS.

### Targets: machines *and* websites

A target can be the local box (`ssh: false`, host `127.0.0.1`), a remote host over
SSH (`ssh: true` — enables Lynis from inside), or a **website / web address**
(`ssh: false` + a real host or `url:`). A website is *web-only*: the outside-in
scanners (nmap, nuclei, testssl, nikto) run against it and Lynis is skipped.

```yaml
targets:
  - id: mysite
    host: example.com
    ssh: false
    url: https://example.com
```

> Only add hosts and sites you own or are explicitly authorized to test. The
> allowlist is the control, and every action is written to the audit log.

## Status

**Detection** (Lynis, Nmap, Nuclei, testssl.sh, Nikto, OpenVAS) **plus gated active
testing** (nuclei DAST, ffuf, sqlmap, OWASP ZAP) behind the `pentest`/`exploit` tiers.
Exploitation is limited to proving impact (e.g. sqlmap reaching the DBMS) and only on
`lab` targets; it never dumps table data. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Tests

```bash
pip install -e ".[dev]" && pytest -q
```
