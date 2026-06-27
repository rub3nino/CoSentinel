#!/usr/bin/env python3
"""Run a full local hackathon demo scan against demo/cosentinel-vuln-demo."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_REPO = ROOT / "demo" / "cosentinel-vuln-demo"
FILE_URL = DEMO_REPO.as_uri()


def main() -> int:
    if not DEMO_REPO.is_dir():
        print(f"Demo repo missing: {DEMO_REPO}", file=sys.stderr)
        return 1

    sys.path.insert(0, str(ROOT))
    import config
    import scan_service

    print("CoSentinel local demo scan")
    print(f"  repo: {FILE_URL}")
    print(f"  live scan: {'ON' if config.ENABLE_LIVE_SCAN else 'OFF (hackathon-safe)'}")
    print(f"  trivy: {shutil_which('trivy')}")
    print(f"  semgrep: {shutil_which('semgrep')}")
    print()

    result = scan_service.scan_repository(FILE_URL, "", None)

    print(f"Duration: {result['duration_sec']}s | Findings: {result['stats']['critical']}C / {result['stats']['high']}H / {result['stats']['medium']}M")
    print()

    print("=== Scanner status ===")
    for name, st in sorted(result.get("scanner_status", {}).items()):
        print(f"  {name:16} {st.get('status', '?'):5}  findings={st.get('findings', 0)}")

    print()
    print("=== Entry points (attack graph) ===")
    for ep in result.get("entry_points", []):
        print(f"  [{ep['severity']}] {ep['status']:9} {ep['title']}")
        print(f"           likelihood={ep['likelihood']}  findings={', '.join(ep['finding_ids'][:4])}")

    print()
    print("=== Sample findings by category ===")
    by_cat: dict[str, list] = {}
    for f in result.get("findings", []):
        by_cat.setdefault(f["category"], []).append(f)
    for cat in ("container", "exposure", "github_actions", "crtsh", "wayback", "auth", "route", "code"):
        items = by_cat.get(cat, [])
        if not items:
            continue
        print(f"  {cat}:")
        for f in items[:3]:
            print(f"    - [{f['severity']}] {f['title']}")

    if result.get("scan_errors"):
        print()
        print("=== Scan notes ===")
        for err in result["scan_errors"][:5]:
            print(f"  ! {err}")

    out = ROOT / "demo" / "last_demo_scan.json"
    out.write_text(json.dumps({k: result[k] for k in result if k != "report"}, indent=2), encoding="utf-8")
    print()
    print(f"Saved summary (no report body): {out}")
    if result.get("report"):
        report_path = ROOT / "demo" / "last_demo_report.md"
        report_path.write_text(result["report"], encoding="utf-8")
        print(f"Saved AI report: {report_path}")

    eps = result.get("entry_points", [])
    ok = any("Container" in ep["title"] for ep in eps) and any(
        "supply-chain" in ep["title"].lower() or "CI/CD" in ep["title"] or "Poisonable" in ep["title"] for ep in eps
    )
    if not ok:
        print("\nWarning: expected container + CI entry points — check demo repo content.", file=sys.stderr)
        return 2
    return 0


def shutil_which(name: str) -> str:
    import shutil

    return shutil.which(name) or "not installed"


if __name__ == "__main__":
    raise SystemExit(main())
