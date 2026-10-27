"""Engine dry-run (plans without executing) and the HTML report renderer."""

import pytest

from cosentinel.adapters.nmap import NmapAdapter
from cosentinel.core.engine import Engine
from cosentinel.core.findings import Category, Finding, Severity
from cosentinel.core.profiles import Intensity, get_profile
from cosentinel.core.scope import AuditLog, AuthorizationError, Scope, Target
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
    assert planned_tools == {"lynis", "nmap", "nuclei", "testssl", "nikto"}

    # The nmap plan targets the host; lynis plans a sudo audit.
    nmap_run = next(r for r in ts.runs if r.adapter == "nmap")
    assert "127.0.0.1" in nmap_run.planned[0].argv
    lynis_run = next(r for r in ts.runs if r.adapter == "lynis")
    assert lynis_run.planned[0].sudo is True


def test_web_only_target_skips_inside_adapters(tmp_path):
    scope = Scope([Target("mysite", "example.com", ssh=False, url="https://example.com")],
                  audit=AuditLog(tmp_path / "audit.jsonl"))
    engine = Engine(scope, Store(tmp_path / "db.sqlite"))
    [ts] = engine.run(["mysite"], get_profile("full"), dry_run=True)

    planned = {r.adapter for r in ts.runs if r.planned}
    # Lynis (inside-host) is skipped; only outside-in scanners are planned.
    assert planned == {"nmap", "nuclei", "testssl", "nikto"}
    lynis_run = next(r for r in ts.runs if r.adapter == "lynis")
    assert lynis_run.skipped and "web-only" in lynis_run.skipped


def test_effective_intensity_window():
    a = NmapAdapter()
    # Clamped down to the adapter's own ceiling, never above it.
    assert a.effective_intensity(Intensity.EXPLOIT) == Intensity.AGGRESSIVE
    assert a.effective_intensity(Intensity.SAFE) == Intensity.SAFE
    # Below the floor, the adapter does not run at all.
    a.min_intensity = Intensity.AGGRESSIVE
    assert a.effective_intensity(Intensity.SAFE) is None
    assert a.effective_intensity(Intensity.AGGRESSIVE) == Intensity.AGGRESSIVE


def test_pentest_profile_clamps_each_adapter_to_its_ceiling(tmp_path):
    scope = Scope([Target("box", "10.0.0.5", ssh=True)],
                  audit=AuditLog(tmp_path / "audit.jsonl"))
    engine = Engine(scope, Store(tmp_path / "db.sqlite"))
    [ts] = engine.run(["box"], get_profile("pentest"), confirmed=True, dry_run=True)

    # Nmap goes aggressive (vuln NSE engaged) under the pentest ceiling…
    nmap_run = next(r for r in ts.runs if r.adapter == "nmap")
    assert nmap_run.intensity == Intensity.AGGRESSIVE
    assert "--script" in nmap_run.planned[0].argv

    # …while a safe-capped adapter still runs, just clamped down to SAFE
    # (it is NOT skipped the way the old model would have skipped it).
    nikto_run = next(r for r in ts.runs if r.adapter == "nikto")
    assert nikto_run.intensity == Intensity.SAFE
    assert nikto_run.planned and nikto_run.skipped is None


def test_pentest_profile_requires_confirm(tmp_path):
    scope = Scope([Target("box", "10.0.0.5", ssh=True)],
                  audit=AuditLog(tmp_path / "audit.jsonl"))
    engine = Engine(scope, Store(tmp_path / "db.sqlite"))
    with pytest.raises(AuthorizationError):
        engine.run(["box"], get_profile("pentest"), confirmed=False, dry_run=True)


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
