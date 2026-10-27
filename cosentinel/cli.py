"""Command-line interface — everything you do with Cosentinel from the terminal.

    cosentinel init                      create a starter config
    cosentinel targets                   list the allowlist
    cosentinel adapters                  list scanners and whether tools are present
    cosentinel profiles                  list scan profiles
    cosentinel scan <target...>          run a scan (‑‑profile, ‑‑confirm, ‑‑dry-run)
    cosentinel report <target> [-o f]    write a static HTML report
    cosentinel diff <target>             what changed since the previous scan
    cosentinel history [target]          past scans
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, adapters  # importing adapters registers them
from .adapters.base import all_adapters
from .config import init_project, load
from .core.correlate import correlate
from .core.engine import Engine
from .core.findings import Severity
from .core.profiles import BUILTIN_PROFILES, get_profile
from .core.scope import AuthorizationError
from .core.store import Store
from .report import render_report
from .transport.ssh import LocalRunner

# Optional pretty output; degrade gracefully to plain print.
try:
    from rich.console import Console
    from rich.table import Table
    _console = Console()
except Exception:  # pragma: no cover
    _console = None


def _print(msg: str = "") -> None:
    if _console:
        _console.print(msg)
    else:
        print(_strip_markup(msg))


def _strip_markup(s: str) -> str:
    import re
    return re.sub(r"\[/?[a-z0-9 #]+\]", "", s)


def _sev_markup(sev: Severity) -> str:
    color = {
        Severity.CRITICAL: "magenta", Severity.HIGH: "red", Severity.MEDIUM: "yellow",
        Severity.LOW: "blue", Severity.INFO: "dim",
    }[sev]
    return f"[{color}]{sev.label}[/{color}]"


# -- commands -------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    cfg = init_project(args.dir)
    _print(f"[green]Created[/green] {cfg}")
    _print("Edit it to add your targets, then run: [bold]cosentinel scan <id>[/bold]")
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    if _console:
        t = Table(title=f"Targets · {cfg.source}")
        for col in ("id", "host", "access", "sudo", "lab", "tags"):
            t.add_column(col)
        for tg in cfg.targets:
            t.add_row(
                tg.id, tg.host, "local" if tg.is_local else "ssh",
                "yes" if tg.sudo else "no", "yes" if tg.lab else "no",
                ",".join(tg.tags),
            )
        _console.print(t)
    else:
        for tg in cfg.targets:
            print(f"{tg.id}\t{tg.host}\t{'local' if tg.is_local else 'ssh'}")
    return 0


def cmd_adapters(args: argparse.Namespace) -> int:
    local = LocalRunner()
    if _console:
        t = Table(title="Scanner adapters")
        for col in ("adapter", "tool", "runs from", "intensity", "tool on this host"):
            t.add_column(col)
        for a in all_adapters():
            window = (a.max_intensity.label if a.min_intensity == a.max_intensity
                      else f"{a.min_intensity.label}→{a.max_intensity.label}")
            t.add_row(
                a.name, a.requires_tool,
                "inside target" if a.runs_on == "target" else "scanner → target",
                window,
                # a.available() honors overrides (COSENTINEL_ZAP / GVM_CLI),
                # which a raw which(requires_tool) would miss.
                "[green]yes[/green]" if a.available(local) else "[red]no[/red]",
            )
        _console.print(t)
    else:
        for a in all_adapters():
            print(f"{a.name}\t{a.requires_tool}\t{a.available(local)}")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    for p in BUILTIN_PROFILES.values():
        _print(f"[bold]{p.name}[/bold] · {p.intensity.label} · {', '.join(p.adapters)}")
        _print(f"    {p.description}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    scope = cfg.scope()
    profile = get_profile(args.profile)

    targets = args.targets
    if args.all:
        targets = [t.id for t in cfg.targets]
    if not targets:
        _print("[red]No targets given.[/red] Pass target ids or --all.")
        return 2

    store = Store(cfg.db_path)
    engine = Engine(scope, store, log=_print)

    try:
        for tid in targets:
            _print(f"\n[bold]▶ {tid}[/bold] · profile {profile.name} ({profile.intensity.label})")
            ts = engine.run([tid], profile, confirmed=args.confirm, dry_run=args.dry_run)[0]
            if args.dry_run:
                _print("  [dim]dry-run — commands that WOULD run:[/dim]")
                for run in ts.runs:
                    if run.skipped:
                        _print(f"    [{run.adapter}] skipped: {run.skipped}")
                    for pc in run.planned:
                        sudo = "sudo " if pc.sudo else ""
                        _print(f"    [{run.adapter}@{run.runner}] {sudo}{' '.join(pc.argv)}")
                continue
            _summarize(ts)
    except AuthorizationError as e:
        _print(f"[red]Refused:[/red] {e}")
        return 3
    return 0


def _summarize(ts) -> None:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in ts.findings:
        counts[f.severity] += 1
    parts = [f"{_sev_markup(s)} {counts[s]}" for s in sorted(Severity, reverse=True) if counts[s]]
    _print("  " + (" · ".join(parts) if parts else "[dim]no findings[/dim]")
           + f"   [dim](scan #{ts.scan_id})[/dim]")


def cmd_report(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    store = Store(cfg.db_path)
    scan_id = store.latest_scan_id(args.target)
    if scan_id is None:
        _print(f"[red]No completed scan[/red] for {args.target!r}. Run a scan first.")
        return 1
    findings = store.findings(scan_id)
    meta = next((s for s in store.scans(args.target) if s["id"] == scan_id), {})
    risks = [r for r in correlate(findings) if r.severity >= Severity.LOW or r.exposed]
    group = {
        "target": args.target,
        "profile": meta.get("profile", ""),
        "intensity": meta.get("intensity", ""),
        "scanned_at": meta.get("finished_at", "") or meta.get("started_at", ""),
        "findings": findings,
        "risks": risks,
    }
    logo = _load_logo()
    html = render_report([group], logo_svg=logo, title=f"Cosentinel · {args.target}")
    out = Path(args.output or f"cosentinel-report-{args.target}.html")
    out.write_text(html, encoding="utf-8")
    _print(f"[green]Wrote[/green] {out}  ({len(findings)} findings)")
    return 0


def cmd_risks(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    store = Store(cfg.db_path)
    scan_id = store.latest_scan_id(args.target)
    if scan_id is None:
        _print(f"[red]No completed scan[/red] for {args.target!r}. Run a scan first.")
        return 1
    risks = [r for r in correlate(store.findings(scan_id))
             if r.severity >= Severity.LOW or r.exposed]
    if not risks:
        _print("[dim]No prioritized risks (only informational findings).[/dim]")
        return 0
    if _console:
        t = Table(title=f"Prioritized risks · {args.target}")
        for col in ("#", "score", "severity", "asset", "sources", "why it matters"):
            t.add_column(col, overflow="fold")
        for i, r in enumerate(risks, 1):
            t.add_row(str(i), str(r.score), _sev_markup(r.severity), r.key,
                      ",".join(r.sources), r.rationale)
        _console.print(t)
    else:
        for i, r in enumerate(risks, 1):
            print(f"{i}\t{r.score}\t{r.severity.label}\t{r.key}\t{r.rationale}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    store = Store(cfg.db_path)
    d = store.diff(args.target)
    _print(f"[bold green]New[/bold green] ({len(d['new'])}):")
    for f in sorted(d["new"], key=lambda x: int(x.severity), reverse=True):
        _print(f"  + {_sev_markup(f.severity)} {f.title}")
    _print(f"[bold blue]Resolved[/bold blue] ({len(d['resolved'])}):")
    for f in d["resolved"]:
        _print(f"  - {f.title}")
    _print(f"[dim]Unchanged: {len(d['unchanged'])}[/dim]")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    cfg = load(args.config)
    store = Store(cfg.db_path)
    for s in store.scans(args.target):
        _print(f"#{s['id']}  {s['target']:<16} {s['profile']:<8} {s['status']:<7} {s['started_at']}")
    return 0


# -- parser ---------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cosentinel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"cosentinel {__version__}")
    p.add_argument("-c", "--config", help="path to config file")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a starter config")
    s.add_argument("--dir", default=".", help="where to create it")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("targets", help="list the allowlist")
    s.set_defaults(func=cmd_targets)

    s = sub.add_parser("adapters", help="list scanners and tool availability")
    s.set_defaults(func=cmd_adapters)

    s = sub.add_parser("profiles", help="list scan profiles")
    s.set_defaults(func=cmd_profiles)

    s = sub.add_parser("scan", help="run a scan")
    s.add_argument("targets", nargs="*", help="target id(s) from the config")
    s.add_argument("--all", action="store_true", help="scan every target in scope")
    s.add_argument("-p", "--profile", default="full", help="profile name (default: full)")
    s.add_argument("--confirm", action="store_true",
                   help="authorize aggressive+ intensity (required for those)")
    s.add_argument("--dry-run", action="store_true",
                   help="show the exact commands without running them")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("report", help="write a static HTML report")
    s.add_argument("target")
    s.add_argument("-o", "--output", help="output file")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("risks", help="correlated, prioritized risks for a target")
    s.add_argument("target")
    s.set_defaults(func=cmd_risks)

    s = sub.add_parser("diff", help="what changed since the previous scan")
    s.add_argument("target")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("history", help="list past scans")
    s.add_argument("target", nargs="?")
    s.set_defaults(func=cmd_history)

    return p


def _load_logo() -> str:
    candidates = [
        Path(__file__).resolve().parent.parent / "assets" / "logo" / "cosentinel-logo.svg",
        Path("assets/logo/cosentinel-logo.svg"),
    ]
    for c in candidates:
        try:
            if c.exists():
                return c.read_text(encoding="utf-8")
        except OSError:
            pass
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, RuntimeError, KeyError, ValueError) as e:
        _print(f"[red]Error:[/red] {e}")
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        _print("\n[dim]interrupted[/dim]")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
