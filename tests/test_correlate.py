"""Correlation & prioritization tests."""

from cosentinel.core.correlate import asset_key, correlate, extract_port
from cosentinel.core.findings import Category, Finding, Severity


def F(source, sev, cat, title, resource, refs=None):
    return Finding(source, "srv", sev, cat, title, resource, references=refs or [])


def test_extract_port_variants():
    assert extract_port(F("nmap", Severity.INFO, Category.NETWORK, "p", "22/tcp")) == 22
    assert extract_port(F("testssl", Severity.LOW, Category.TLS, "x", "cert_x:443")) == 443
    assert extract_port(F("nuclei", Severity.HIGH, Category.VULNERABILITY, "x", "http://h:8080/a")) == 8080
    assert extract_port(F("lynis", Severity.MEDIUM, Category.HARDENING, "x", "SSH-7408")) == 22
    assert extract_port(F("lynis", Severity.LOW, Category.HARDENING, "x", "FIRE-4513")) is None
    assert asset_key(F("lynis", Severity.LOW, Category.HARDENING, "x", "FIRE-4513")) == "host hardening"


def test_ssh_weakness_and_open_port_reinforce_each_other():
    findings = [
        F("nmap", Severity.INFO, Category.NETWORK, "Open port 22/tcp: ssh", "22/tcp"),
        F("lynis", Severity.MEDIUM, Category.HARDENING, "SSH root login permitted", "SSH-7408"),
        F("lynis", Severity.LOW, Category.HARDENING, "Enable the firewall", "FIRE-4513"),
    ]
    risks = correlate(findings)
    top = risks[0]
    # The open port and the SSH hardening weakness land on the same asset.
    assert top.key == "port 22"
    assert set(top.sources) == {"lynis", "nmap"}
    assert top.exposed is True and top.severity is Severity.MEDIUM
    # reachable AND weak (+8) and corroborated by 2 tools (+5) on top of MEDIUM(20)
    assert top.score == 20 + 5 + 8
    assert "reachable from the network AND weak" in top.rationale
    # The lone firewall suggestion is a separate, lower-ranked risk.
    assert risks[-1].key == "host hardening"


def test_cve_raises_score_and_rationale():
    findings = [
        F("nmap", Severity.INFO, Category.NETWORK, "Open port 443/tcp", "443/tcp"),
        F("nuclei", Severity.HIGH, Category.VULNERABILITY, "RCE", "https://h:443/x", refs=["CVE-2021-41773"]),
    ]
    r = correlate(findings)[0]
    assert r.key == "port 443" and r.has_cve
    assert r.exposed and r.severity is Severity.HIGH
    assert "known CVE" in r.rationale


def test_exposed_medium_outranks_isolated_low():
    findings = [
        F("lynis", Severity.LOW, Category.HARDENING, "minor", "AUTH-1"),
        F("nmap", Severity.MEDIUM, Category.NETWORK, "telnet exposed", "23/tcp"),
    ]
    risks = correlate(findings)
    assert risks[0].key == "port 23"
    assert risks[0].score > risks[1].score
