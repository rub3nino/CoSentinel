"""Adapter parser tests — fed real sample output from each tool.

These are the reliability tests: they pin down exactly how each scanner's output
becomes findings, so a tool version bump that changes output is caught here
rather than silently producing garbage.
"""

from cosentinel.adapters.lynis import LynisAdapter
from cosentinel.adapters.nmap import NmapAdapter
from cosentinel.adapters.nuclei import NucleiAdapter
from cosentinel.adapters.testssl import TestsslAdapter
from cosentinel.core.findings import Category, Severity
from cosentinel.core.profiles import Intensity
from cosentinel.core.scope import Target
from cosentinel.transport.ssh import CommandResult


def _result(stdout="", stderr="", rc=0):
    return CommandResult(argv=["x"], returncode=rc, stdout=stdout, stderr=stderr, duration=0.1)


TARGET = Target("srv", "10.0.0.5", url="http://10.0.0.5")


# -- nmap -----------------------------------------------------------------
NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.9p1"/>
   </port>
   <port protocol="tcp" portid="23">
    <state state="open"/>
    <service name="telnet"/>
   </port>
   <port protocol="tcp" portid="81">
    <state state="closed"/>
    <service name="http"/>
   </port>
  </ports>
 </host>
</nmaprun>"""


def test_nmap_parses_open_ports_and_flags_telnet():
    findings = NmapAdapter().parse([_result(NMAP_XML)], TARGET, Intensity.SAFE)
    titles = [f.title for f in findings]
    # ssh open port -> INFO network finding
    assert any("22/tcp" in t and "ssh" in t for t in titles)
    # telnet -> MEDIUM risky-service finding
    telnet = [f for f in findings if "telnet" in f.title.lower()]
    assert telnet and telnet[0].severity is Severity.MEDIUM
    # closed port is ignored (not counted among open ports)
    summary = [f for f in findings if f.title.startswith("Nmap:")][0]
    assert "2 open port" in summary.title


def test_nmap_handles_garbage_output():
    findings = NmapAdapter().parse([_result("not xml", stderr="boom")], TARGET, Intensity.SAFE)
    assert findings and findings[0].severity is Severity.INFO


# -- nuclei ---------------------------------------------------------------
NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-41773","matched-at":"http://10.0.0.5/cgi-bin",'
    '"info":{"name":"Apache Path Traversal","severity":"high",'
    '"description":"Path traversal in Apache 2.4.49",'
    '"classification":{"cve-id":["CVE-2021-41773"]}}}\n'
    '{"template-id":"tls-version","matched-at":"10.0.0.5:443",'
    '"info":{"name":"TLS 1.0 enabled","severity":"low","tags":["ssl","tls"]}}\n'
)


def test_nuclei_maps_severity_and_cve():
    findings = NucleiAdapter().parse([_result(NUCLEI_JSONL)], TARGET, Intensity.SAFE)
    high = [f for f in findings if f.severity is Severity.HIGH][0]
    assert high.category == Category.VULNERABILITY
    assert "CVE-2021-41773" in high.references
    tls = [f for f in findings if "TLS" in f.title][0]
    assert tls.category == Category.TLS and tls.severity is Severity.LOW


def test_nuclei_no_matches_gives_info():
    findings = NucleiAdapter().parse([_result("")], TARGET, Intensity.SAFE)
    assert findings and findings[0].severity is Severity.INFO


# -- lynis ----------------------------------------------------------------
LYNIS_REPORT = """\
# lynis report
hardening_index=63
warning[]=SSH-7408|SSH root login is permitted|-|-|
suggestion[]=AUTH-9262|Install a password strength tool|-|-|
suggestion[]=FIRE-4513|Enable the firewall|-|-|
"""


def test_lynis_parses_warnings_suggestions_and_index():
    findings = LynisAdapter().parse(
        [_result("audit ran"), _result(LYNIS_REPORT)], TARGET, Intensity.SAFE
    )
    warn = [f for f in findings if f.resource == "SSH-7408"][0]
    assert warn.severity is Severity.MEDIUM and "root login" in warn.title
    sugg = [f for f in findings if f.resource == "FIRE-4513"][0]
    assert sugg.severity is Severity.LOW
    idx = [f for f in findings if f.resource == "hardening_index"][0]
    assert "63/100" in idx.title


def test_lynis_no_report_is_reported_not_crashed():
    findings = LynisAdapter().parse([_result("", stderr="sudo: no"), _result("")],
                                    TARGET, Intensity.SAFE)
    assert findings and findings[0].severity is Severity.INFO


# -- testssl --------------------------------------------------------------
# testssl.sh flat --jsonfile output: a JSON array of check results.
TESTSSL_JSON = """[
  {"id":"SSLv2","ip":"ex/1.2.3.4","port":"443","severity":"OK","finding":"not offered"},
  {"id":"cert_chain_of_trust","ip":"ex","port":"443","severity":"HIGH","finding":"failed (chain incomplete)"},
  {"id":"cert_expirationStatus","port":"443","severity":"WARN","finding":"expires < 60 days"},
  {"id":"TLS1","port":"443","severity":"LOW","finding":"offered (deprecated)"},
  {"id":"heartbleed","port":"443","severity":"INFO","finding":"not vulnerable"},
  {"id":"BEAST","port":"443","severity":"MEDIUM","finding":"VULNERABLE","cve":"CVE-2011-3389"}
]"""


def test_testssl_keeps_problems_and_drops_healthy_lines():
    findings = TestsslAdapter().parse(
        [_result("scan done"), _result(TESTSSL_JSON)], TARGET, Intensity.SAFE
    )
    # OK and INFO lines (SSLv2, heartbleed) are dropped; 4 real issues remain.
    assert len(findings) == 4
    assert all(f.category == Category.TLS for f in findings)
    sev_by_id = {f.raw["id"]: f.severity for f in findings}
    assert sev_by_id["cert_chain_of_trust"] is Severity.HIGH
    assert sev_by_id["cert_expirationStatus"] is Severity.MEDIUM   # WARN -> MEDIUM
    assert sev_by_id["TLS1"] is Severity.LOW
    beast = [f for f in findings if f.raw["id"] == "BEAST"][0]
    assert "CVE-2011-3389" in beast.references


def test_testssl_clean_target_gives_info():
    findings = TestsslAdapter().parse(
        [_result("scan done"), _result("[]")], TARGET, Intensity.SAFE
    )
    assert len(findings) == 1 and findings[0].severity is Severity.INFO


def test_testssl_no_json_is_reported_not_crashed():
    findings = TestsslAdapter().parse(
        [_result("", stderr="connection refused"), _result("")], TARGET, Intensity.SAFE
    )
    assert findings and findings[0].severity is Severity.INFO
