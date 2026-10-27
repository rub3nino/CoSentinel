"""Core domain tests: findings, severity, scope/authorization, store + diff."""

import pytest

from cosentinel.core.findings import Category, Finding, Severity
from cosentinel.core.profiles import Intensity, get_profile
from cosentinel.core.scope import AuditLog, AuthorizationError, Scope, Target
from cosentinel.core.store import Store


def test_severity_parse_and_order():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("WARNING") is Severity.MEDIUM
    assert Severity.parse("nonsense") is Severity.INFO
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_fingerprint_is_stable_and_ignores_timestamps():
    a = Finding("nmap", "srv", Severity.LOW, Category.NETWORK, "Open port 22/tcp", "22/tcp")
    b = Finding("nmap", "srv", Severity.HIGH, Category.NETWORK, "Open port 22/tcp", "22/tcp",
                first_seen="2020", last_seen="2021")
    # Same identity => same fingerprint even though severity/time differ.
    assert a.fingerprint == b.fingerprint
    c = Finding("nmap", "srv", Severity.LOW, Category.NETWORK, "Open port 80/tcp", "80/tcp")
    assert a.fingerprint != c.fingerprint


def test_scope_rejects_unknown_target(tmp_path):
    scope = Scope([Target("a", "1.2.3.4")], audit=AuditLog(tmp_path / "audit.jsonl"))
    with pytest.raises(AuthorizationError):
        scope.authorize("ghost", Intensity.SAFE)


def test_scope_safe_is_allowed_without_confirm(tmp_path):
    scope = Scope([Target("a", "1.2.3.4")], audit=AuditLog(tmp_path / "audit.jsonl"))
    t = scope.authorize("a", Intensity.SAFE)
    assert t.id == "a"


def test_scope_aggressive_needs_confirm(tmp_path):
    scope = Scope([Target("a", "1.2.3.4")], audit=AuditLog(tmp_path / "audit.jsonl"))
    with pytest.raises(AuthorizationError):
        scope.authorize("a", Intensity.AGGRESSIVE, confirmed=False)
    assert scope.authorize("a", Intensity.AGGRESSIVE, confirmed=True).id == "a"


def test_scope_exploit_needs_lab_even_with_confirm(tmp_path):
    scope = Scope(
        [Target("prod", "1.2.3.4", lab=False), Target("lab", "5.6.7.8", lab=True)],
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )
    with pytest.raises(AuthorizationError):
        scope.authorize("prod", Intensity.EXPLOIT, confirmed=True)
    assert scope.authorize("lab", Intensity.EXPLOIT, confirmed=True).id == "lab"


def test_audit_log_records_authorizations(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    scope = Scope([Target("a", "1.2.3.4")], audit=AuditLog(log_path))
    scope.authorize("a", Intensity.SAFE)
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1 and '"action": "authorize"' in lines[0]


def test_store_roundtrip_and_diff(tmp_path):
    store = Store(tmp_path / "db.sqlite")

    # first scan: two findings
    s1 = store.start_scan("srv", "full", "Safe")
    store.add_finding(s1, Finding("nmap", "srv", Severity.LOW, Category.NETWORK, "port 22", "22/tcp"))
    store.add_finding(s1, Finding("nmap", "srv", Severity.MEDIUM, Category.NETWORK, "telnet", "23/tcp"))
    store.finish_scan(s1)

    # second scan: telnet resolved, a new ssh-weakness appears
    s2 = store.start_scan("srv", "full", "Safe")
    store.add_finding(s2, Finding("nmap", "srv", Severity.LOW, Category.NETWORK, "port 22", "22/tcp"))
    store.add_finding(s2, Finding("lynis", "srv", Severity.MEDIUM, Category.HARDENING, "weak ssh", "SSH-7408"))
    store.finish_scan(s2)

    d = store.diff("srv")
    titles = lambda fs: sorted(f.title for f in fs)
    assert titles(d["new"]) == ["weak ssh"]
    assert titles(d["resolved"]) == ["telnet"]
    assert titles(d["unchanged"]) == ["port 22"]


def test_profiles_exist_and_are_safe_by_default():
    for name in ("audit", "network", "vuln", "full"):
        p = get_profile(name)
        assert p.intensity == Intensity.SAFE
    with pytest.raises(KeyError):
        get_profile("exploit-everything")
