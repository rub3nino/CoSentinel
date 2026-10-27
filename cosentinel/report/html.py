"""Static HTML report — the read-only 'vetrina'.

This is a tool *output*, not the marketing website: a single self-contained
file you open in a browser to look at a scan. It executes nothing and talks to
nothing; it just shows findings. The marketing site is a separate, later
deliverable.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from ..core.findings import Finding, Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#8b1f67",
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#b9770e",
    Severity.LOW: "#186dad",
    Severity.INFO: "#5b6470",
}

_CSS = """
:root{
  --accent:#baca01; --ink:#1E293B; --muted:#5b6470;
  --bg:#F8FAFC; --surface:#FFFFFF; --border:#e3e8ef;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 "Fira Sans",system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 80px}
header{display:flex;align-items:center;gap:16px;margin-bottom:8px}
header .logo{width:52px;height:52px;flex:0 0 auto}
header .logo svg{width:100%;height:100%;display:block}
header h1{font-size:22px;margin:0;letter-spacing:-.01em}
.sub{color:var(--muted);margin:2px 0 28px}
.counts{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 28px}
.chip{border:1px solid var(--border);background:var(--surface);border-radius:10px;
  padding:10px 14px;min-width:92px}
.chip b{display:block;font-size:22px;line-height:1.1}
.chip span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.group{background:var(--surface);border:1px solid var(--border);border-radius:14px;
  margin-bottom:22px;overflow:hidden}
.group>h2{margin:0;padding:14px 18px;border-bottom:1px solid var(--border);font-size:16px}
.group>h2 small{color:var(--muted);font-weight:400}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:11px 18px;border-bottom:1px solid var(--border);
  vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:none}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;
  font-size:12px;font-weight:600;white-space:nowrap}
.res{font-family:"Fira Code",ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12.5px;color:var(--muted)}
.title b{display:block}
.title p{margin:3px 0 0;color:var(--muted);font-size:13px}
.title .rem{margin-top:6px;font-size:13px}
.refs{font-size:12px}
footer{margin-top:34px;color:var(--muted);font-size:12.5px;text-align:center}
.empty{padding:22px 18px;color:var(--muted)}
"""


def _sev_badge(sev: Severity) -> str:
    return f'<span class="sev" style="background:{_SEV_COLOR[sev]}">{html.escape(sev.label)}</span>'


def _row(f: Finding) -> str:
    refs = ""
    if f.references:
        refs = '<div class="refs">' + ", ".join(html.escape(r) for r in f.references) + "</div>"
    rem = f'<div class="rem"><b>Fix:</b> {html.escape(f.remediation)}</div>' if f.remediation else ""
    desc = f"<p>{html.escape(f.description)}</p>" if f.description else ""
    return (
        "<tr>"
        f"<td>{_sev_badge(f.severity)}</td>"
        f'<td class="res">{html.escape(f.source)}<br>{html.escape(f.resource)}</td>'
        f'<td class="title"><b>{html.escape(f.title)}</b>{desc}{rem}{refs}</td>'
        "</tr>"
    )


def _group_block(meta: dict) -> str:
    findings: list[Finding] = sorted(
        meta["findings"], key=lambda f: int(f.severity), reverse=True
    )
    head = (
        f'<h2>{html.escape(meta["target"])} '
        f'<small>· profile {html.escape(meta.get("profile",""))} '
        f'· {html.escape(meta.get("intensity",""))} '
        f'· {html.escape(meta.get("scanned_at",""))}</small></h2>'
    )
    if not findings:
        return f'<section class="group">{head}<div class="empty">No findings.</div></section>'
    rows = "".join(_row(f) for f in findings)
    table = (
        "<table><thead><tr><th>Severity</th><th>Source</th>"
        "<th>Finding</th></tr></thead><tbody>" + rows + "</tbody></table>"
    )
    return f'<section class="group">{head}{table}</section>'


def render_report(groups: list[dict], *, logo_svg: str = "", title: str = "Cosentinel report") -> str:
    """Render a self-contained HTML report.

    `groups` is a list of dicts: {target, profile, intensity, scanned_at, findings}.
    """
    totals: dict[Severity, int] = {s: 0 for s in Severity}
    for g in groups:
        for f in g["findings"]:
            totals[f.severity] += 1

    chips = "".join(
        f'<div class="chip"><b style="color:{_SEV_COLOR[s]}">{totals[s]}</b>'
        f"<span>{html.escape(s.label)}</span></div>"
        for s in sorted(Severity, reverse=True)
    )
    logo = logo_svg or ""
    body = "".join(_group_block(g) for g in groups) or '<p class="empty">Nothing to show.</p>'
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>"
        '<div class="wrap">'
        f'<header><div class="logo">{logo}</div><h1>{html.escape(title)}</h1></header>'
        f'<p class="sub">Read-only security posture report · generated {generated}</p>'
        f'<div class="counts">{chips}</div>'
        f"{body}"
        '<footer>Cosentinel — local security posture orchestrator. '
        "This report executes nothing; it only displays findings.</footer>"
        "</div></body></html>"
    )
