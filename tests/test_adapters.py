"""Adapter parser tests — fed real sample output from each tool.

These are the reliability tests: they pin down exactly how each scanner's output
becomes findings, so a tool version bump that changes output is caught here
rather than silently producing garbage.
"""

from cosentinel.adapters.lynis import LynisAdapter
from cosentinel.adapters.nikto import NiktoAdapter
from cosentinel.adapters.nmap import NmapAdapter
from cosentinel.adapters.nuclei import NucleiAdapter
from cosentinel.adapters.openvas import OpenvasAdapter
from cosentinel.adapters.sqlmap import SqlmapAdapter
from cosentinel.adapters.testssl import TestsslAdapter
from cosentinel.adapters.ffuf import FfufAdapter
from cosentinel.adapters.zap import ZapAdapter
from cosentinel.core.findings import Category, Severity
from cosentinel.core.profiles import Intensity
from cosentinel.core.scope import Target
from cosentinel.transport.ssh import CommandResult


def _result(stdout="", stderr="", rc=0):
    return CommandResult(argv=["x"], returncode=rc, stdout=stdout, stderr=stderr, duration=0.1)


TARGET = Target("srv", "10.0.0.5", url="http://10.0.0.5")


# -- sqlmap ---------------------------------------------------------------
SQLMAP_VULN = """
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.2#stable}

[12:00:05] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable
sqlmap identified the following injection point(s) with a total of 54 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND SLEEP(5)
---
[12:00:30] [INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
"""

SQLMAP_EXPLOIT = SQLMAP_VULN + """
banner: '5.7.38-0ubuntu0.18.04.1'
current user: 'webapp@localhost'
current database: 'shop'
current user is DBA: False
available databases [3]:
[*] information_schema
[*] mysql
[*] shop
"""


def test_sqlmap_never_runs_in_a_safe_scan():
    # min_intensity is AGGRESSIVE, so a SAFE ceiling must not run it at all.
    assert SqlmapAdapter().effective_intensity(Intensity.SAFE) is None
    assert SqlmapAdapter().effective_intensity(Intensity.EXPLOIT) == Intensity.EXPLOIT


def test_sqlmap_detection_reports_injectable_parameter():
    out = SqlmapAdapter().parse([_result(SQLMAP_VULN)], TARGET, Intensity.AGGRESSIVE)
    highs = [f for f in out if f.severity is Severity.HIGH]
    assert len(highs) == 1
    f = highs[0]
    assert "id" in f.title and f.category is Category.VULNERABILITY
    assert "MySQL" in f.description
    assert "CWE-89" in f.references
    # Detection-only: no proof-of-impact CRITICAL finding.
    assert not [x for x in out if x.severity is Severity.CRITICAL]


def test_sqlmap_exploit_adds_impact_finding():
    out = SqlmapAdapter().parse([_result(SQLMAP_EXPLOIT)], TARGET, Intensity.EXPLOIT)
    crit = [f for f in out if f.severity is Severity.CRITICAL]
    assert len(crit) == 1
    assert "shop" in crit[0].description
    assert crit[0].raw["databases"] == ["information_schema", "mysql", "shop"]


def test_sqlmap_not_injectable_and_unreachable():
    clean = SqlmapAdapter().parse(
        [_result("[12:00:40] [WARNING] all tested parameters do not appear to be injectable.")],
        TARGET, Intensity.AGGRESSIVE)
    assert len(clean) == 1 and clean[0].severity is Severity.INFO
    assert "no SQL injection" in clean[0].title

    down = SqlmapAdapter().parse(
        [_result("[critical] unable to connect to the target URL")],
        TARGET, Intensity.AGGRESSIVE)
    assert len(down) == 1 and "could not reach" in down[0].title


def test_sqlmap_crawl_link_failure_is_not_target_unreachable():
    # The scan-#12 trap: sqlmap DID reach and test the target, but a secondary
    # crawled link failed to connect (a [WARNING], not [critical]). That must
    # read as "reached, clean" — never as "could not reach the target", which
    # would hide the fact that a real test ran.
    out = (
        "[21:41:32] [INFO] starting crawler for target URL 'http://10.0.0.5'\n"
        "[21:41:33] [INFO] heuristics detected web page charset 'utf-8'\n"
        "[21:42:10] [WARNING] unable to connect to the target URL ('https://cdn/asset.js')\n"
        "[21:45:00] [WARNING] all tested parameters do not appear to be injectable.\n"
    )
    res = SqlmapAdapter().parse([_result(out)], TARGET, Intensity.AGGRESSIVE)
    assert len(res) == 1 and res[0].severity is Severity.INFO
    assert "no SQL injection" in res[0].title
    assert "could not reach" not in res[0].title
    # And the stdout tail is kept for debugging (old findings stored {}).
    assert res[0].raw.get("stdout_tail")


def test_sqlmap_no_forms_is_its_own_outcome():
    res = SqlmapAdapter().parse(
        [_result("[INFO] there were no forms found at the given target URL")],
        TARGET, Intensity.AGGRESSIVE)
    assert len(res) == 1 and res[0].severity is Severity.INFO
    assert "no testable parameters or forms" in res[0].title


def test_sqlmap_handles_laravel_csrf_token_by_default():
    # Without this, --batch answers the "update anti-CSRF token?" prompt with
    # the default No, so a Laravel login form is tested with a stale _token and
    # every request is rejected (false negative).
    argv = SqlmapAdapter().plan(TARGET, Intensity.AGGRESSIVE)[0].argv
    assert "--csrf-token=_token" in argv
    assert "--forms" in argv


def test_sqlmap_csrf_token_is_configurable(monkeypatch):
    monkeypatch.setenv("COSENTINEL_SQLMAP_CSRF_TOKEN", "authenticity_token")
    monkeypatch.setenv("COSENTINEL_SQLMAP_CSRF_URL", "http://10.0.0.5/login")
    argv = SqlmapAdapter().plan(TARGET, Intensity.AGGRESSIVE)[0].argv
    assert "--csrf-token=authenticity_token" in argv
    assert "--csrf-url=http://10.0.0.5/login" in argv

    # Empty value disables it entirely (stays a generic query-param scanner).
    monkeypatch.setenv("COSENTINEL_SQLMAP_CSRF_TOKEN", "")
    argv = SqlmapAdapter().plan(TARGET, Intensity.AGGRESSIVE)[0].argv
    assert not any(a.startswith("--csrf-token") for a in argv)


# Time-based-only injection reported while the target was rate-limiting — the
# exact false-positive trap from the real Coolify run.
SQLMAP_TIMEBASED_RATELIMITED = """
[09:05:04] [WARNING] target appears to be rate-limiting requests; sqlmap is backing off and throttling accordingly
sqlmap identified the following injection point(s) with a total of 120 HTTP(s) requests:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=x' AND SLEEP(5)-- -
---
back-end DBMS: MySQL >= 5.0.12
"""
# Same, but no throttling in sight: a time-based hit on a healthy target stands.
SQLMAP_TIMEBASED_CLEAN = SQLMAP_TIMEBASED_RATELIMITED.replace(
    "[09:05:04] [WARNING] target appears to be rate-limiting requests; "
    "sqlmap is backing off and throttling accordingly\n", "")
# A clean-timing re-run that confirms the param via a non-timing technique.
SQLMAP_EMAIL_CONFIRMED = """
sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: email=x' AND 1=1-- -
---
back-end DBMS: MySQL >= 5.0.12
"""
SQLMAP_EMAIL_CLEARED = (
    "[10:09:48] [WARNING] POST parameter 'email' does not seem to be injectable\n"
    "[10:09:48] [ERROR] all tested parameters do not appear to be injectable.")


class _StubRunner:
    """Feeds canned sqlmap output per run() call, in order."""
    def __init__(self, *outputs):
        self._outputs = list(outputs)
        self.calls = []

    def which(self, tool):  # pragma: no cover - not used here
        return True

    def run(self, argv, timeout=None, sudo=False):
        self.calls.append(argv)
        out = self._outputs.pop(0)
        return CommandResult(argv=argv, returncode=0, stdout=out, stderr="", duration=0.1)


def test_sqlmap_time_based_under_rate_limit_is_downgraded():
    from cosentinel.core.correlate import correlate
    f = SqlmapAdapter().parse(
        [_result(SQLMAP_TIMEBASED_RATELIMITED)], TARGET, Intensity.AGGRESSIVE)
    vuln = [x for x in f if x.category is Category.VULNERABILITY]
    assert len(vuln) == 1
    # Not a HIGH confirmation — a MEDIUM suspicion.
    assert vuln[0].severity is Severity.MEDIUM
    assert "suspected" in vuln[0].title.lower()
    assert vuln[0].raw["time_based_only"] and vuln[0].raw["rate_limited"]
    assert vuln[0].raw["confidence"] == "low"
    # And crucially it must NOT inflate the risk as "actively confirmed".
    risk = correlate(vuln)[0]
    assert not risk.actively_confirmed


def test_sqlmap_time_based_without_rate_limit_stays_high():
    f = SqlmapAdapter().parse(
        [_result(SQLMAP_TIMEBASED_CLEAN)], TARGET, Intensity.AGGRESSIVE)
    vuln = [x for x in f if x.category is Category.VULNERABILITY]
    assert len(vuln) == 1 and vuln[0].severity is Severity.HIGH
    assert "suspected" not in vuln[0].title.lower()


def test_sqlmap_plan_applies_proactive_delay(monkeypatch):
    monkeypatch.setenv("COSENTINEL_SQLMAP_DELAY", "2")
    argv = SqlmapAdapter().plan(TARGET, Intensity.AGGRESSIVE)[0].argv
    assert "--delay=2" in argv


def test_sqlmap_autoverify_confirms_promotes_to_high():
    runner = _StubRunner(SQLMAP_TIMEBASED_RATELIMITED, SQLMAP_EMAIL_CONFIRMED)
    out = SqlmapAdapter().scan(runner, TARGET, Intensity.AGGRESSIVE)
    assert len(runner.calls) == 2                         # re-ran to verify
    assert "-p" in runner.calls[1] and "--delay=1" in runner.calls[1]
    vuln = [f for f in out if f.category is Category.VULNERABILITY]
    assert len(vuln) == 1 and vuln[0].severity is Severity.HIGH
    assert "suspected" not in vuln[0].title.lower()


def test_sqlmap_autoverify_clears_false_positive():
    runner = _StubRunner(SQLMAP_TIMEBASED_RATELIMITED, SQLMAP_EMAIL_CLEARED)
    out = SqlmapAdapter().scan(runner, TARGET, Intensity.AGGRESSIVE)
    assert len(runner.calls) == 2
    assert not [f for f in out if f.severity >= Severity.HIGH]
    assert not [f for f in out if f.severity is Severity.MEDIUM]
    assert any("not confirmed" in f.title.lower() for f in out)


def test_sqlmap_autoverify_can_be_disabled(monkeypatch):
    monkeypatch.setenv("COSENTINEL_SQLMAP_AUTOVERIFY", "0")
    runner = _StubRunner(SQLMAP_TIMEBASED_RATELIMITED)
    out = SqlmapAdapter().scan(runner, TARGET, Intensity.AGGRESSIVE)
    assert len(runner.calls) == 1                         # no re-run
    assert [f for f in out if f.severity is Severity.MEDIUM]


# -- zap ------------------------------------------------------------------
ZAP_JSON = """{
  "site": [{
    "@name": "https://example.com",
    "alerts": [
      {
        "pluginid": "40018", "alert": "SQL Injection", "name": "SQL Injection",
        "riskcode": "3", "confidence": "2",
        "desc": "<p>SQL injection may be possible.</p>",
        "solution": "<p>Use parameterized queries.</p>",
        "reference": "<p>https://owasp.org/sqli</p>", "cweid": "89",
        "instances": [{"uri": "https://example.com/item?id=1", "method": "GET", "param": "id"}]
      },
      {
        "pluginid": "10020", "alert": "Missing Anti-clickjacking Header",
        "name": "Missing Anti-clickjacking Header", "riskcode": "2", "confidence": "2",
        "desc": "<p>X-Frame-Options not set.</p>", "solution": "<p>Set the header.</p>",
        "reference": "", "cweid": "1021", "instances": []
      }
    ]
  }]
}"""


def test_zap_is_aggressive_only():
    assert ZapAdapter().effective_intensity(Intensity.SAFE) is None
    assert ZapAdapter().effective_intensity(Intensity.AGGRESSIVE) == Intensity.AGGRESSIVE


def test_zap_parses_alerts_with_risk_and_cwe():
    # parse() reads the LAST result (the `cat` of the JSON report).
    out = ZapAdapter().parse([_result(""), _result(""), _result(ZAP_JSON)],
                             TARGET, Intensity.AGGRESSIVE)
    assert len(out) == 2
    sqli = next(f for f in out if "SQL Injection" in f.title)
    assert sqli.severity is Severity.HIGH and sqli.category is Category.WEB
    assert "CWE-89" in sqli.references
    assert "<p>" not in sqli.description  # HTML stripped
    assert sqli.resource == "https://example.com/item?id=1"
    header = next(f for f in out if "clickjacking" in f.title.lower())
    assert header.severity is Severity.MEDIUM


def test_zap_cmd_override_switches_launcher(monkeypatch):
    from cosentinel.adapters.zap import _zap_cmd
    monkeypatch.setenv("COSENTINEL_ZAP", "/x/zap-native.sh")
    scan_cmd = ZapAdapter().plan(TARGET, Intensity.AGGRESSIVE)[1].argv
    assert scan_cmd[0] == "/x/zap-native.sh"
    assert "-t" in scan_cmd and TARGET.web_target in scan_cmd
    monkeypatch.delenv("COSENTINEL_ZAP")
    assert _zap_cmd() == ["zap-full-scan.py"]


def test_zap_no_report_is_informational():
    out = ZapAdapter().parse([_result(""), _result("", "zap crashed"), _result("")],
                             TARGET, Intensity.AGGRESSIVE)
    assert len(out) == 1 and out[0].severity is Severity.INFO
    assert "no report" in out[0].title


# -- ffuf -----------------------------------------------------------------
FFUF_JSON = """{
  "results": [
    {"input": {"FUZZ": "admin"}, "status": 200, "length": 512, "url": "http://10.0.0.5/admin"},
    {"input": {"FUZZ": ".git"}, "status": 301, "length": 0, "url": "http://10.0.0.5/.git"},
    {"input": {"FUZZ": "images"}, "status": 301, "length": 0, "url": "http://10.0.0.5/images"}
  ]
}"""


def test_ffuf_is_aggressive_only():
    assert FfufAdapter().effective_intensity(Intensity.SAFE) is None


def test_ffuf_enables_auto_calibration():
    # -ac filters catch-all 200s (SPAs), so discovery isn't all false positives.
    argv = FfufAdapter().plan(TARGET, Intensity.AGGRESSIVE)[1].argv
    assert "-ac" in argv


def test_ffuf_flags_sensitive_paths_higher():
    out = FfufAdapter().parse([_result(""), _result(""), _result(FFUF_JSON)],
                              TARGET, Intensity.AGGRESSIVE)
    assert len(out) == 3
    git = next(f for f in out if ".git" in f.resource)
    assert git.severity is Severity.MEDIUM          # sensitive name, even on a 301
    admin = next(f for f in out if "admin" in f.resource)
    assert admin.severity is Severity.MEDIUM         # sensitive name + 200
    images = next(f for f in out if "images" in f.resource)
    assert images.severity is Severity.INFO          # plain 301, not sensitive


def test_ffuf_without_wordlist_is_informational(monkeypatch):
    monkeypatch.delenv("COSENTINEL_WORDLIST", raising=False)
    monkeypatch.setattr("cosentinel.adapters.ffuf._wordlist", lambda: None)
    out = FfufAdapter().parse([_result(""), _result("", "no wordlist given"), _result("")],
                              TARGET, Intensity.AGGRESSIVE)
    assert len(out) == 1 and "wordlist" in out[0].title


# -- nuclei intensity -----------------------------------------------------
def test_nuclei_enables_dast_only_when_aggressive():
    a = NucleiAdapter()
    safe = a.plan(TARGET, Intensity.SAFE)[0].argv
    assert "-dast" not in safe
    aggressive = a.plan(TARGET, Intensity.AGGRESSIVE)[0].argv
    assert "-dast" in aggressive


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


def test_testssl_terse_grade_gets_readable_title():
    # overall_grade reports the bare grade ("T") as its finding text; on its own
    # that is a useless title, so it must be prefixed with the humanized id.
    data = '[{"id":"overall_grade","port":"443","severity":"CRITICAL","finding":"T"}]'
    f = TestsslAdapter().parse([_result("scan done"), _result(data)], TARGET, Intensity.SAFE)[0]
    assert f.title == "Overall grade: T"
    assert f.severity is Severity.CRITICAL


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


def test_testssl_skips_local_engine_warning():
    # testssl emits an `engine_problem` WARN about the scanner's own openssl;
    # it must not become a finding about the target.
    data = """[
      {"id":"engine_problem","port":"443","severity":"WARN","finding":"No engine or GOST support via engine with your openssl"},
      {"id":"cert_chain_of_trust","port":"443","severity":"HIGH","finding":"self signed"}
    ]"""
    findings = TestsslAdapter().parse([_result("x"), _result(data)], TARGET, Intensity.SAFE)
    assert len(findings) == 1 and findings[0].raw["id"] == "cert_chain_of_trust"


def test_testssl_failure_is_distinct_from_clean(tmp_path=None):
    # 3-command shape (rm, scan, cat). Empty report + scan error => "did not
    # produce a report", NOT a false "no issues found".
    results = [_result("rm"),
               _result("", stderr='Fatal error: non-empty "..." exists', rc=1),
               _result("")]
    f = TestsslAdapter().parse(results, TARGET, Intensity.SAFE)[0]
    assert f.severity is Severity.INFO and "did not produce a report" in f.title
    # Truly clean target (empty, no error) reads as "no TLS issues found".
    clean = TestsslAdapter().parse([_result("rm"), _result(""), _result("")],
                                   TARGET, Intensity.SAFE)[0]
    assert "no TLS issues found" in clean.title


# -- nikto ----------------------------------------------------------------
NIKTO_JSON = """{
  "host":"10.0.0.5","ip":"10.0.0.5","port":"80","banner":"Apache/2.4.49",
  "vulnerabilities":[
    {"id":"999103","method":"GET","url":"/","msg":"The anti-clickjacking X-Frame-Options header is not present."},
    {"id":"999970","method":"GET","url":"/","msg":"Server may leak inodes via ETags"},
    {"id":"600449","method":"GET","url":"/cgi-bin/","msg":"Apache 2.4.49 appears vulnerable to path traversal","references":"CVE-2021-41773"}
  ]
}"""


def test_nikto_parses_vulns_and_bumps_severity():
    findings = NiktoAdapter().parse(
        [_result("scan done"), _result(NIKTO_JSON)], TARGET, Intensity.SAFE
    )
    assert len(findings) == 3
    assert all(f.category == Category.WEB for f in findings)
    # path-traversal item has a CVE -> MEDIUM, with the CVE referenced
    trav = [f for f in findings if "traversal" in f.title.lower()][0]
    assert trav.severity is Severity.MEDIUM and "CVE-2021-41773" in trav.references
    # a plain missing-header item stays LOW
    header = [f for f in findings if "X-Frame-Options" in f.title][0]
    assert header.severity is Severity.LOW
    assert header.resource == "GET /"


def test_nikto_accepts_array_form_and_empty():
    assert NiktoAdapter().parse([_result("x"), _result('[{"vulnerabilities":[]}]')],
                                TARGET, Intensity.SAFE)[0].severity is Severity.INFO


def test_nikto_no_json_is_reported_not_crashed():
    findings = NiktoAdapter().parse([_result("", stderr="host down"), _result("")],
                                    TARGET, Intensity.SAFE)
    assert findings and findings[0].severity is Severity.INFO


# -- openvas (GMP report XML parsing) -------------------------------------
OPENVAS_XML = """<get_reports_response status="200">
 <report><report><results>
  <result>
    <name>OpenSSL Infinite Loop DoS</name>
    <host>10.0.0.5</host>
    <port>443/tcp</port>
    <threat>High</threat>
    <severity>7.5</severity>
    <description>Vulnerable OpenSSL version detected.</description>
    <nvt oid="1.3.6.1.4.1.25623.1.0.1">
      <name>OpenSSL DoS</name>
      <cve>CVE-2022-0778</cve>
      <tags>summary=BN_mod_sqrt loop|solution=Upgrade OpenSSL|qod_type=remote</tags>
    </nvt>
  </result>
  <result>
    <name>TCP timestamps</name>
    <host>10.0.0.5</host><port>general/tcp</port>
    <threat>Log</threat><severity>0.0</severity>
    <nvt oid="1.2.3"><name>TCP timestamps</name><cve>NOCVE</cve></nvt>
  </result>
 </results></report></report>
</get_reports_response>"""


def test_openvas_parses_report():
    fs = OpenvasAdapter().parse([_result(OPENVAS_XML)], TARGET, Intensity.SAFE)
    high = [f for f in fs if f.severity is Severity.HIGH][0]
    assert high.category == Category.VULNERABILITY
    assert "CVE-2022-0778" in high.references
    assert "Upgrade OpenSSL" in high.remediation
    assert high.resource == "10.0.0.5 443/tcp"
    log = [f for f in fs if f.severity is Severity.INFO][0]
    assert log.references == []            # NOCVE is filtered out


def test_openvas_empty_report_is_reported():
    fs = OpenvasAdapter().parse([_result("<get_reports_response/>")], TARGET, Intensity.SAFE)
    assert fs and fs[0].severity is Severity.INFO
    fs2 = OpenvasAdapter().parse([_result("")], TARGET, Intensity.SAFE)
    assert fs2 and "empty report" in fs2[0].title


def test_openvas_cli_override(monkeypatch):
    from cosentinel.adapters.openvas import _cli
    monkeypatch.delenv("GVM_CLI", raising=False)
    assert _cli() == ["gvm-cli"]
    monkeypatch.setenv("GVM_CLI", "docker compose exec -T gvm-tools gvm-cli")
    assert _cli()[0] == "docker" and _cli()[-1] == "gvm-cli"
