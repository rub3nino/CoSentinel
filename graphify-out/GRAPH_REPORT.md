# Graph Report - CoSentinel  (2026-06-27)

## Corpus Check
- 43 files · ~48,431 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 536 nodes · 770 edges · 49 communities (46 shown, 3 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 91 edges (avg confidence: 0.75)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `7adfb727`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]

## God Nodes (most connected - your core abstractions)
1. `Finding` - 45 edges
2. `BackendSmokeTest` - 32 edges
3. `build_entry_points()` - 17 edges
4. `scanner_status` - 15 edges
5. `scan_repository()` - 14 edges
6. `list_all_scan_history()` - 14 edges
7. `create_fix_pr()` - 13 edges
8. `_save_cache()` - 12 edges
9. `ServerHttpTest` - 12 edges
10. `scan_network()` - 12 edges

## Surprising Connections (you probably didn't know these)
- `create_fix_pr()` --calls--> `can_fix()`  [INFERRED]
  pr_creator.py → fix_patches.py
- `delete_scan()` --calls--> `delete_scan_record()`  [INFERRED]
  server.py → scan_service.py
- `create_pr()` --calls--> `create_fix_pr()`  [INFERRED]
  server.py → pr_creator.py
- `_apply_patch_commit()` --calls--> `validate_patch()`  [INFERRED]
  pr_creator.py → fix_patches.py
- `_apply_patch_commit()` --calls--> `apply_unified_diff()`  [INFERRED]
  pr_creator.py → fix_patches.py

## Communities (49 total, 3 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.11
Nodes (5): Finding, Passive OSINT via Internet Archive CDX — historical URLs for declared domains., Query Wayback CDX for archived sensitive paths. Passive — no probing of live hos, scan_wayback(), BackendSmokeTest

### Community 1 - "Community 1"
Cohesion: 0.14
Nodes (13): Architettura CoSentinel — Riferimento Rapido per Codex, code:block1 (You are Builder A for CoSentinel, an AI-powered GitHub repos), code:block2, code:block3, code:block4, code:block5 (Report any errors back.), code:block6 (CoSentinel/), code:block7 (GitHub URL + token) (+5 more)

### Community 2 - "Community 2"
Cohesion: 0.10
Nodes (20): CLAUDE CODE (other terminal) — Builder B, code:block1 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/fet), code:block2 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/sca), code:block3 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/sca), code:block4 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/sca), code:block5 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/sca), code:block6 (Create the file `/Users/ruben/Progetti/estera/CoSentinel/age), code:block7 (Create TWO files:) (+12 more)

### Community 3 - "Community 3"
Cohesion: 0.18
Nodes (10): code:block1 (You are Builder B for CoSentinel, an AI-powered GitHub repos), code:block2, code:block3, code:block4, code:block5, code:bash (cd /Users/ruben/Progetti/CoSentinel), code:block7, code:block8 (+2 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (21): commit_sha, duration_sec, entry_points, findings, finished_at, live_target, repo_name, scan_errors (+13 more)

### Community 5 - "Community 5"
Cohesion: 0.09
Nodes (45): _append_exposure_section(), _attach_fix_patches(), _cache_path(), _dedupe_findings(), delete_scan_record(), _emit(), get_cache_metadata(), get_scan_record() (+37 more)

### Community 7 - "Community 7"
Cohesion: 0.11
Nodes (21): fetch_repo(), list_repo_files(), _local_repo_path(), _normalize_repo_url(), _repo_key(), _repo_name_from_url(), Run git log and scan added lines for secrets.     Return [] on any failure., scan_git_history() (+13 more)

### Community 11 - "Community 11"
Cohesion: 0.50
Nodes (3): _config_type(), scan_config(), scan_exposure()

### Community 14 - "Community 14"
Cohesion: 0.11
Nodes (17): C1: Extend `scanners/code.py` — add PHP, Ruby, Go, Bash patterns, C2: Extend `scanners/secrets.py` — add more patterns, C3: Add `scanners/git_history.py` — scan git log for accidentally committed secrets, C4: Update `server.py` — add git_history to pipeline + add /api/health endpoint, code:block1 (.php → "php"), code:python ("git_findings": len(git_findings)), code:bash (python3 -c "import server; print('server updated OK')"), code:python (PHP_PATTERNS = {) (+9 more)

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (16): 2a: Replace fetch POST with EventSource SSE, 2b: Progress steps now show REAL labels from SSE, 2c: Add findings count badge to navbar when scan completes, 2d: Add "Copy Report" button next to "Download Report", 2e: Improve finding cards, code:python (from fastapi.responses import StreamingResponse), code:javascript (// OLD: fetch POST), code:block3 (● 47 findings  (red dot if any CRITICAL/HIGH, yellow if MEDI) (+8 more)

### Community 16 - "Community 16"
Cohesion: 0.16
Nodes (19): _apply_patch_commit(), _apply_unified_diff(), _branch_name(), _can_fix(), create_fix_pr(), _gh(), _gh_patch(), _gh_post() (+11 more)

### Community 17 - "Community 17"
Cohesion: 0.09
Nodes (27): BaseModel, ScanResult, Severity, _deserialize_finding(), get_cached_findings(), _cache_key(), _cache_path(), create_pr() (+19 more)

### Community 18 - "Community 18"
Cohesion: 0.10
Nodes (25): API, Built at, code:block1 (GitHub URL (+ optional live target)), code:bash (pip3 install fastapi uvicorn openai requests python-dotenv g), code:bash (# .env — only on your machine, never on a public deployment), code:bash (brew install trivy nuclei semgrep), code:bash (brew install trivy nuclei   # container base CVEs + live mis), code:bash (python3 -m unittest discover -s tests -q) (+17 more)

### Community 19 - "Community 19"
Cohesion: 0.08
Nodes (23): 0. Why this doc exists, 1.1 Color tokens (light) — "document grey + scan blue", 1.2 Spacing / radius / shadow / z (token scales), 1.3 Fonts, 1. Skill verdict (ui-ux-pro-max), 2. Phases (each = what / how / why-rule), 3. Ponytail cut (deliberate skips), 4. Build order (impact ÷ effort) (+15 more)

### Community 20 - "Community 20"
Cohesion: 0.32
Nodes (16): _check_dns(), _check_headers(), _check_tls(), _extract_grep(), _extract_port_line(), _gobuster(), _next_id(), _nikto() (+8 more)

### Community 21 - "Community 21"
Cohesion: 0.17
Nodes (18): build_entry_points(), _by_category(), _container_risks(), _critical_deps(), _critical_github_actions(), _critical_secrets(), _deploy_targets(), EntryPoint (+10 more)

### Community 23 - "Community 23"
Cohesion: 0.43
Nodes (5): _configish(), _extract_from_text(), _normalize_url(), _scan_file(), scan_targets()

### Community 25 - "Community 25"
Cohesion: 0.50
Nodes (4): collect_domains(), Passive subdomain discovery via crt.sh certificate transparency logs., _root_domain(), scan_crtsh()

### Community 26 - "Community 26"
Cohesion: 0.18
Nodes (10): Attack Chains, code:bash (git checkout -b harden/dependencies), Critical & High Findings, Executive Summary, [EXP-001] Dockerfile: Declared exposed port, [EXP-002] docker-compose: Public bind on all interfaces, Exposure Findings, Fix‑Ready Findings (+2 more)

### Community 27 - "Community 27"
Cohesion: 0.47
Nodes (5): analyze(), _format_entry_points(), _format_findings(), get_available_models(), get_models()

### Community 28 - "Community 28"
Cohesion: 0.67
Nodes (3): GitHub Actions workflow security — CI/CD poison and supply-chain patterns., scan_github_actions(), _workflow_files()

### Community 29 - "Community 29"
Cohesion: 0.20
Nodes (9): 1. One-time setup, 2. Run scan (CLI), 3. Run scan (UI), code:bash (# CLI scanners (optional but recommended)), code:bash (python3 scripts/run_demo_scan.py), code:bash (uvicorn server:app --port 8000), code:block4 (file:///Users/ruben/Progetti/CoSentinel/demo/cosentinel-vuln), Expected entry points (INFERRED) (+1 more)

### Community 30 - "Community 30"
Cohesion: 0.40
Nodes (4): code:bash (docker compose up --build), CoSentinel Hackathon Demo API, Deployment, Run locally

### Community 31 - "Community 31"
Cohesion: 0.40
Nodes (5): errors, findings, status, scanner_status, auth

### Community 32 - "Community 32"
Cohesion: 0.40
Nodes (5): domains, errors, findings, status, crtsh

### Community 33 - "Community 33"
Cohesion: 0.40
Nodes (5): wayback, domains, errors, findings, status

### Community 35 - "Community 35"
Cohesion: 0.50
Nodes (4): errors, findings, status, code

### Community 36 - "Community 36"
Cohesion: 0.50
Nodes (4): errors, findings, status, config

### Community 37 - "Community 37"
Cohesion: 0.50
Nodes (4): errors, findings, status, deps

### Community 38 - "Community 38"
Cohesion: 0.50
Nodes (4): errors, findings, status, exposure

### Community 39 - "Community 39"
Cohesion: 0.50
Nodes (4): errors, findings, status, git_history

### Community 40 - "Community 40"
Cohesion: 0.50
Nodes (4): errors, findings, status, github_actions

### Community 41 - "Community 41"
Cohesion: 0.50
Nodes (4): errors, findings, status, routes

### Community 42 - "Community 42"
Cohesion: 0.50
Nodes (4): secrets, errors, findings, status

### Community 43 - "Community 43"
Cohesion: 0.50
Nodes (4): semgrep, errors, findings, status

### Community 44 - "Community 44"
Cohesion: 0.50
Nodes (4): targets, errors, findings, status

### Community 45 - "Community 45"
Cohesion: 0.50
Nodes (4): trivy, errors, findings, status

### Community 47 - "Community 47"
Cohesion: 0.13
Nodes (18): apply_unified_diff(), attach_fix_patches(), can_fix(), _fix_line(), issue_name(), _mask_env_secret(), _propose_fix(), Generate and validate mechanical auto-fix patches for PR creation. (+10 more)

### Community 48 - "Community 48"
Cohesion: 0.33
Nodes (9): _extract_fixed_version(), _find_dependency_files(), _parse_gemfile_lock(), _parse_go_mod(), _parse_package_json(), _parse_pom_xml(), _parse_requirements(), scan_dependencies() (+1 more)

## Knowledge Gaps
- **155 isolated node(s):** `scan_id`, `findings`, `entry_points`, `suggested_targets`, `critical` (+150 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Finding` connect `Community 0` to `Community 6`, `Community 7`, `Community 47`, `Community 48`, `Community 17`, `Community 20`, `Community 21`, `Community 23`, `Community 25`?**
  _High betweenness centrality (0.125) - this node is a cross-community bridge._
- **Why does `EntryPoint` connect `Community 21` to `Community 0`, `Community 17`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Why does `_deserialize_finding()` connect `Community 17` to `Community 0`, `Community 5`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `Finding` (e.g. with `EntryPoint` and `BackendSmokeTest`) actually correct?**
  _`Finding` has 44 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `BackendSmokeTest` (e.g. with `Finding` and `Severity`) actually correct?**
  _`BackendSmokeTest` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `str` (e.g. with `scan()` and `create_pr()`) actually correct?**
  _`str` has 16 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Creates a GitHub PR with auto-fixes for the specified finding_ids.     Returns t`, `SSE endpoint: streams progress events then the final result.`, `Every scan across all repositories, newest first.` to the rest of the system?**
  _197 weakly-connected nodes found - possible documentation gaps or missing edges._