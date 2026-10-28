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
    # nmap only reported the port OPEN (INFO), so it doesn't "corroborate" the
    # weakness — that reachability is already credited as "reachable AND weak"
    # (+8). Only lynis found an actual problem, so there's no multi-tool bonus.
    assert top.corroborating_sources == ["lynis"]
    assert top.score == 20 + 8
    assert "reachable from the network AND weak" in top.rationale
    assert "corroborated by" not in top.rationale
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


def test_active_sqli_on_open_web_port_tops_the_list():
    findings = [
        F("nmap", Severity.INFO, Category.NETWORK, "Open port 443/tcp", "443/tcp"),
        F("sqlmap", Severity.HIGH, Category.VULNERABILITY,
          "SQL injection in parameter 'id' (GET)", "https://h (param: id [GET])", refs=["CWE-89"]),
    ]
    r = correlate(findings)[0]
    # The web finding (no explicit port) maps to 443 and joins the open port.
    assert r.key == "port 443"
    assert r.actively_confirmed and r.exposed
    assert "actively confirmed exploitable" in r.rationale
    # Only sqlmap found a real problem (nmap just saw the port open), so no
    # multi-tool bonus: HIGH(30) + reachable&weak(8) + actively confirmed(10).
    assert r.corroborating_sources == ["sqlmap"]
    assert r.score == 30 + 8 + 10
    assert "corroborated by" not in r.rationale


def test_info_only_sources_do_not_corroborate():
    # The real Coolify case: one real finding (zap MEDIUM) plus a crowd of tools
    # that found nothing (nmap open-port, nuclei no-match, testssl no-issues,
    # sqlmap couldn't-reach). The rationale must not claim "corroborated by 5".
    findings = [
        F("zap", Severity.MEDIUM, Category.WEB, "CSP header not set", "http://h:8000"),
        F("nmap", Severity.INFO, Category.NETWORK, "Open port 8000/tcp", "8000/tcp"),
        F("nuclei", Severity.INFO, Category.INFO, "no template matches", "http://h:8000"),
        F("testssl", Severity.INFO, Category.INFO, "no TLS issues", "http://h:8000"),
        F("sqlmap", Severity.INFO, Category.INFO, "could not reach", "http://h:8000"),
    ]
    r = correlate(findings)[0]
    assert r.key == "port 8000"
    assert r.corroborating_sources == ["zap"]
    assert "corroborated by" not in r.rationale
    # No phantom +5: MEDIUM(20) + reachable&weak(8), nothing for the INFO crowd.
    assert r.score == 20 + 8


def test_two_real_findings_do_corroborate():
    findings = [
        F("zap", Severity.MEDIUM, Category.WEB, "CSP header not set", "http://h:8000"),
        F("nikto", Severity.LOW, Category.WEB, "missing X-Content-Type-Options", "http://h:8000"),
        F("nmap", Severity.INFO, Category.NETWORK, "Open port 8000/tcp", "8000/tcp"),
    ]
    r = correlate(findings)[0]
    assert r.corroborating_sources == ["nikto", "zap"]
    assert "corroborated by 2 tools (nikto, zap)" in r.rationale
    assert r.score == 20 + 5 + 8          # MEDIUM + corroboration + reachable&weak


def test_exposed_medium_outranks_isolated_low():
    findings = [
        F("lynis", Severity.LOW, Category.HARDENING, "minor", "AUTH-1"),
        F("nmap", Severity.MEDIUM, Category.NETWORK, "telnet exposed", "23/tcp"),
    ]
    risks = correlate(findings)
    assert risks[0].key == "port 23"
    assert risks[0].score > risks[1].score
