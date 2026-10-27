"""Engine dry-run (plans without executing) and the HTML report renderer."""

from cosentinel.core.engine import Engine
from cosentinel.core.findings import Category, Finding, Severity
from cosentinel.core.profiles import get_profile
from cosentinel.core.scope import AuditLog, Scope, Target
from cosentinel.core.store import Store
from cosentinel.report import render_report


def test_engine_dry_run_plans_but_does_not_execute(tmp_path):
    scope = Scope([Target("localhost", "127.0.0.1", ssh=False, sudo=True, lab=True)],
                  audit=AuditLog(tmp_path / "audit.jsonl"))
    store = Store(tmp_path / "db.sqlite")
    engine = Engine(scope, store)

    [ts] = engine.run(["localhost"], get_profile("full"), dry_run=True)

    # No scan should have been persisted in a dry run.
    assert ts.scan_id is None
    assert store.scans("localhost") == []

    # Every adapter in the profile should have produced a plan.
    planned_tools = {run.adapter for run in ts.runs if run.planned}
    assert planned_tools == {"lynis", "nmap", "nuclei", "testssl"}

    # The nmap plan targets the host; lynis plans a sudo audit.
    nmap_run = next(r for r in ts.runs if r.adapter == "nmap")
    assert "127.0.0.1" in nmap_run.planned[0].argv
    lynis_run = next(r for r in ts.runs if r.adapter == "lynis")
    assert lynis_run.planned[0].sudo is True


def test_report_renders_findings(tmp_path):
    group = {
        "target": "srv", "profile": "full", "intensity": "Safe",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "findings": [
            Finding("nmap", "srv", Severity.MEDIUM, Category.NETWORK,
                    "Risky service exposed: telnet on 23/tcp", "23/tcp",
                    remediation="Disable telnet."),
            Finding("lynis", "srv", Severity.LOW, Category.HARDENING,
                    "Enable the firewall", "FIRE-4513"),
        ],
    }
    html = render_report([group], logo_svg="<svg/>", title="Cosentinel · srv")
    assert "Cosentinel · srv" in html
    assert "telnet" in html
    assert "Medium" in html and "Low" in html
    assert "Disable telnet." in html
