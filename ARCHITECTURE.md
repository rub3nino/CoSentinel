# Cosentinel — Architecture

This is the reference document for how Cosentinel is built and why. It is the
specification we agreed on before writing code.

## 1. What it is

A **local, terminal-first** security-posture orchestrator. You install it in a
folder on your own machine and have full control. It connects to the machines
you own over SSH, orchestrates established scanners, normalizes their output,
and keeps history locally.

It is **not** a scanner (it does not reinvent Lynis/Nmap/Nuclei) and **not** a
hosted service (nothing is exposed to the internet).

## 2. The three load-bearing ideas

Everything else serves these:

1. **Plugin / adapter model** — every scanner is an `Adapter` implementing one
   small interface. Growth = add one file. (`cosentinel/adapters/`)
2. **Intensity tiers** — `passive < safe < aggressive < exploit`. *Finding* a
   weakness and *exploiting* it are different acts behind different gates.
   (`cosentinel/core/profiles.py`)
3. **Scope + audit** — an explicit allowlist, authorization rules over it, and
   an append-only audit log. This is what makes a privileged SSH tool
   trustworthy instead of a footgun. (`cosentinel/core/scope.py`)

## 3. Module map

```
cosentinel/
├── core/
│   ├── findings.py   # the normalized Finding model + Severity + Category
│   ├── profiles.py   # Intensity tiers + named profiles (audit/network/vuln/full)
│   ├── scope.py      # Target, Scope (allowlist + authorize()), AuditLog
│   ├── store.py      # SQLite: scans, findings, history, diff()
│   └── engine.py     # orchestrator: authorize → pick runner → run adapters → store
├── transport/
│   └── ssh.py        # LocalRunner + SSHRunner (the ONLY code that touches a machine)
├── adapters/
│   ├── base.py       # Adapter ABC + registry
│   ├── lynis.py      # hardening audit (runs INSIDE the target)
│   ├── nmap.py       # network surface (runs FROM scanner TOWARD target)
│   └── nuclei.py     # known-vuln detection (FROM scanner TOWARD target)
├── report/
│   └── html.py       # static, read-only HTML report (a tool output, not the website)
├── config.py         # YAML config = the allowlist; .cosentinel/ holds local state
└── cli.py            # the terminal interface
```

### Data flow of one scan

```
cosentinel scan <target> --profile full
        │
        ▼
  config.load() ──► Scope (allowlist)
        │
        ▼
  Engine.run():
     scope.authorize(target, intensity, confirmed)   # gate + audit
        │
        ├─ adapter.runs_on == "target"  ──► runner = SSHRunner/LocalRunner (inside)
        └─ adapter.runs_on == "scanner" ──► runner = LocalRunner (toward target.host)
        │
        ▼
     adapter.plan() → runner.run() → adapter.parse() → [Finding, ...]
        │
        ▼
     Store: scans + findings (SQLite)
        │
        ▼
  cosentinel report / diff / history
```

### The Finding model

Every scanner output becomes a `Finding`:

```
{source, target, severity, category, title, resource,
 description, remediation, references[], raw{}, first_seen, last_seen}
```

Its **fingerprint** = `sha256(source|target|category|resource|title)` and is
stable across runs (it excludes timestamps and severity). That stability is
what makes `diff` ("today vs yesterday") meaningful.

## 4. Where each scanner runs — "inside" vs "outside"

This distinction is the heart of the value:

- **Lynis** is `runs_on = "target"`: it must read the machine's own config, so
  the engine runs it *inside* (SSH, or locally for a local target), with sudo.
- **Nmap / Nuclei** are `runs_on = "scanner"`: they look at the machine *from
  outside*, the way an attacker on the network would. The engine runs them on
  the local host, pointed at `target.host`.

Cosentinel unifies the inside view and the outside view of the same machine —
that is something no single tool gives you.

## 5. Safety model in detail

| Action intensity | Rule enforced by `Scope.authorize()` |
|------------------|---------------------------------------|
| anything         | target **must** be in the allowlist |
| `aggressive`+    | requires explicit `--confirm` |
| `exploit`        | additionally requires `lab: true` on the target |

Every call is recorded in `.cosentinel/audit.jsonl`. `--dry-run` prints the
exact commands before anything executes. SSH uses the system `ssh` binary with
`BatchMode=yes` — Cosentinel never handles your private keys itself.

## 6. Local now, promotable later

The module boundaries are deliberately the same as the layers of a hosted,
multi-user deployment, just collapsed into one process. Nothing has to be
rewritten to promote it later:

| Local module (today)        | Hosted layer (future, if ever) |
|-----------------------------|--------------------------------|
| `transport/` + `adapters/`  | Workers on a private network (behind a queue) |
| `core/engine.py`            | Stateless API |
| `core/scope.py`             | AuthZ + target inventory service |
| `core/store.py` (SQLite)    | PostgreSQL |
| `report/html.py`            | Static frontend |
| CLI                         | (the API's clients) |

The hosted architecture (Cloudflare edge, stateless API, Redis workers,
separate identity, Tailscale-only management) is the **target map**, not the
starting point. We build terminal-first and grow into it only if Cosentinel
ever needs to be multi-user and always-on.

## 7. Roadmap

- **v1 (done):** adapter engine + scope/audit + Lynis + Nmap + Nuclei + SQLite +
  CLI + static report.
- **v2:** more detection adapters — OpenVAS/Greenbone, testssl.sh, ZAP/Nikto;
  CVE correlation (searchsploit); scheduling.
- **v3:** correlation/prioritization across adapters; the marketing website;
  optional local-AI remediation summaries.
- **v4 (gated):** exploitation adapters (Metasploit, …) strictly behind the
  `exploit` tier and `lab`-only targets.

## 8. Adding a new scanner (the common case)

1. Create `cosentinel/adapters/<tool>.py`.
2. Subclass `Adapter`, set `name`, `requires_tool`, `runs_on`, `max_intensity`.
3. Implement `plan()` (the commands) and `parse()` (output → findings).
4. `@register` it and import it in `adapters/__init__.py`.
5. Add a parser test in `tests/test_adapters.py` with real sample output.

No other file needs to change. The `adapter-author` agent in `.claude/agents/`
automates exactly this.
