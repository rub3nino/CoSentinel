# Graph Report - CoSentinel  (2026-06-27)

## Corpus Check
- 23 files · ~20,988 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 260 nodes · 366 edges · 20 communities (16 shown, 4 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 37 edges (avg confidence: 0.72)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `5955b59d`
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

## God Nodes (most connected - your core abstractions)
1. `Finding` - 15 edges
2. `BackendSmokeTest` - 14 edges
3. `_save_cache()` - 12 edges
4. `2. Phases (each = what / how / why-rule)` - 12 edges
5. `create_fix_pr()` - 11 edges
6. `scan_repository()` - 11 edges
7. `ServerHttpTest` - 11 edges
8. `scan_dependencies()` - 11 edges
9. `delete_scan_record()` - 9 edges
10. `Severity` - 9 edges

## Surprising Connections (you probably didn't know these)
- `scans()` --calls--> `list_scan_history()`  [INFERRED]
  server.py → scan_service.py
- `delete_scan()` --calls--> `delete_scan_record()`  [INFERRED]
  server.py → scan_service.py
- `create_pr()` --calls--> `create_fix_pr()`  [INFERRED]
  server.py → pr_creator.py
- `scan()` --calls--> `ScanResult`  [INFERRED]
  server.py → models.py
- `scan_detail()` --calls--> `get_scan_record()`  [INFERRED]
  server.py → scan_service.py

## Communities (20 total, 4 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.16
Nodes (8): BaseModel, Finding, ScanResult, Severity, PRRequest, ScanRequest, Enum, BackendSmokeTest

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
Cohesion: 0.15
Nodes (16): fetch_repo(), list_repo_files(), _normalize_repo_url(), _repo_name_from_url(), _extract_fixed_version(), _find_dependency_files(), _parse_gemfile_lock(), _parse_go_mod() (+8 more)

### Community 5 - "Community 5"
Cohesion: 0.16
Nodes (29): _attach_fix_patches(), _cache_path(), _dedupe_findings(), delete_scan_record(), _emit(), get_cache_metadata(), get_scan_record(), list_scan_history() (+21 more)

### Community 7 - "Community 7"
Cohesion: 0.50
Nodes (4): analyze(), _format_findings(), get_available_models(), get_models()

### Community 14 - "Community 14"
Cohesion: 0.11
Nodes (17): C1: Extend `scanners/code.py` — add PHP, Ruby, Go, Bash patterns, C2: Extend `scanners/secrets.py` — add more patterns, C3: Add `scanners/git_history.py` — scan git log for accidentally committed secrets, C4: Update `server.py` — add git_history to pipeline + add /api/health endpoint, code:block1 (.php → "php"), code:python ("git_findings": len(git_findings)), code:bash (python3 -c "import server; print('server updated OK')"), code:python (PHP_PATTERNS = {) (+9 more)

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (16): 2a: Replace fetch POST with EventSource SSE, 2b: Progress steps now show REAL labels from SSE, 2c: Add findings count badge to navbar when scan completes, 2d: Add "Copy Report" button next to "Download Report", 2e: Improve finding cards, code:python (from fastapi.responses import StreamingResponse), code:javascript (// OLD: fetch POST), code:block3 (● 47 findings  (red dot if any CRITICAL/HIGH, yellow if MEDI) (+8 more)

### Community 16 - "Community 16"
Cohesion: 0.17
Nodes (18): _apply_patch_commit(), _apply_unified_diff(), _branch_name(), _can_fix(), create_fix_pr(), _gh(), _gh_patch(), _gh_post() (+10 more)

### Community 17 - "Community 17"
Cohesion: 0.13
Nodes (18): _deserialize_finding(), get_cached_findings(), _cache_key(), _cache_path(), create_pr(), delete_scan(), _deserialize_finding(), _load_findings() (+10 more)

### Community 18 - "Community 18"
Cohesion: 0.20
Nodes (9): Built at, code:block1 (GitHub URL + token), code:bash (pip3 install fastapi uvicorn openai requests python-dotenv g), CoSentinel — AI-Powered Repository Security Scanner, How it works, Powered by, Run locally, Tech Stack (+1 more)

### Community 19 - "Community 19"
Cohesion: 0.08
Nodes (23): 0. Why this doc exists, 1.1 Color tokens (light) — "document grey + scan blue", 1.2 Spacing / radius / shadow / z (token scales), 1.3 Fonts, 1. Skill verdict (ui-ux-pro-max), 2. Phases (each = what / how / why-rule), 3. Ponytail cut (deliberate skips), 4. Build order (impact ÷ effort) (+15 more)

## Knowledge Gaps
- **74 isolated node(s):** `PreToolUse`, `code:block1 (You are Builder A for CoSentinel, an AI-powered GitHub repos)`, `code:block2`, `code:block3`, `code:block4` (+69 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Finding` connect `Community 0` to `Community 17`, `Community 4`, `Community 6`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Why does `create_pr()` connect `Community 17` to `Community 16`?**
  _High betweenness centrality (0.067) - this node is a cross-community bridge._
- **Why does `create_fix_pr()` connect `Community 16` to `Community 17`?**
  _High betweenness centrality (0.062) - this node is a cross-community bridge._
- **Are the 14 inferred relationships involving `Finding` (e.g. with `BackendSmokeTest` and `ServerHttpTest`) actually correct?**
  _`Finding` has 14 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `BackendSmokeTest` (e.g. with `Finding` and `Severity`) actually correct?**
  _`BackendSmokeTest` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Creates a GitHub PR with auto-fixes for the specified finding_ids.     Returns t`, `Apply fix_patch as a file update commit on the branch.`, `Minimal unified diff applier for single-file patches.` to the rest of the system?**
  _87 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.14285714285714285 - nodes in this community are weakly interconnected._