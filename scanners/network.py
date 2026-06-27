import subprocess
import shutil
import re
import threading
from models import Finding, Severity

_counter = 0
_lock = threading.Lock()


def _next_id() -> str:
    global _counter
    with _lock:
        _counter += 1
        return f"NET-{_counter:03d}"


def _run(cmd: list[str], timeout: int = 90, *, input_text: str | None = None) -> str:
    try:
        r = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return (r.stdout + r.stderr)[:12000]
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]"
    except Exception as e:
        return f"[error: {e}]"


def scan_network(target: str) -> list[Finding]:
    """
    Authorized entry-point validation against a live target (IP, domain, or URL).
    Passive/light checks only: port inventory, HTTP headers, TLS, DNS, optional nikto/gobuster.
    Only call on systems you own or are explicitly authorized to test.
    """
    global _counter
    with _lock:
        _counter = 0

    findings: list[Finding] = []
    host = _normalize_host(target)
    is_web = target.startswith("http://") or target.startswith("https://")
    if not host:
        raise ValueError("Live target must include a host")
    web_url = target if is_web else f"http://{host}"

    findings += _nmap_basic(host)
    findings += _nmap_vuln(host)
    findings += _check_headers(web_url)
    findings += _check_tls(host)
    findings += _check_dns(host)

    if shutil.which("nikto"):
        findings += _nikto(web_url)
    if shutil.which("gobuster"):
        findings += _gobuster(web_url)
    if shutil.which("nuclei"):
        findings += _nuclei(web_url)

    return findings


def _normalize_host(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].split(":")[0]


# ── nmap port + service ────────────────────────────────────────

def _nmap_basic(host: str) -> list[Finding]:
    findings = []
    out = _run(["nmap", "-sV", "-T4", "--open", "-p", "21,22,23,25,80,443,445,3306,3389,5432,6379,8080,8443,27017", host], timeout=60)

    # dangerous open ports
    RISKY_PORTS = {
        "21": ("FTP open", HIGH := Severity.HIGH, "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."),
        "23": ("Telnet open", Severity.CRITICAL, "Telnet is unencrypted. Replace with SSH immediately."),
        "25": ("SMTP open", Severity.MEDIUM, "Open SMTP relay may allow spam abuse. Restrict to authorized senders."),
        "445": ("SMB open", Severity.HIGH, "SMB exposed externally — risk of EternalBlue/ransomware. Firewall this port."),
        "3306": ("MySQL exposed", Severity.HIGH, "MySQL port open externally. Restrict to localhost or VPN only."),
        "3389": ("RDP exposed", Severity.HIGH, "RDP open externally — brute-force target. Use VPN + NLA."),
        "5432": ("PostgreSQL exposed", Severity.HIGH, "PostgreSQL open externally. Restrict to localhost or VPN only."),
        "6379": ("Redis exposed", Severity.CRITICAL, "Redis open externally with no auth by default — trivial RCE."),
        "27017": ("MongoDB exposed", Severity.CRITICAL, "MongoDB open externally — often no auth by default. Firewall immediately."),
        "8080": ("HTTP alt port open", Severity.LOW, "Alternative HTTP port open — verify no dev/admin interface exposed."),
    }

    for port, (title, severity, fix) in RISKY_PORTS.items():
        pattern = rf"{port}/tcp\s+open"
        if re.search(pattern, out):
            findings.append(Finding(
                id=_next_id(),
                severity=severity,
                category="network",
                title=title,
                description=f"Port {port} is open and reachable externally on {host}.",
                file_path=None,
                line_number=None,
                evidence=_extract_port_line(out, port),
                fix_suggestion=fix,
                auto_fixable=False,
            ))

    # detect service versions for known vulns
    if re.search(r"OpenSSH [1-6]\.", out):
        findings.append(Finding(
            id=_next_id(),
            severity=Severity.HIGH,
            category="network",
            title="Outdated OpenSSH version",
            description="Old OpenSSH versions have known RCE and info-disclosure vulnerabilities.",
            file_path=None, line_number=None,
            evidence=_extract_grep(out, "OpenSSH"),
            fix_suggestion="Upgrade OpenSSH to latest stable version.",
            auto_fixable=False,
        ))

    if re.search(r"Apache/2\.[0-3]\.", out) or re.search(r"nginx/1\.[0-9]\.", out):
        findings.append(Finding(
            id=_next_id(),
            severity=Severity.MEDIUM,
            category="network",
            title="Potentially outdated web server",
            description="Web server version may be outdated and expose known CVEs.",
            file_path=None, line_number=None,
            evidence=_extract_grep(out, r"Apache|nginx"),
            fix_suggestion="Upgrade web server and suppress version disclosure (ServerTokens Prod).",
            auto_fixable=False,
        ))

    return findings


def _nmap_vuln(host: str) -> list[Finding]:
    findings = []
    out = _run(["nmap", "--script", "vuln", "-T4", "-p", "80,443,8080,8443", host], timeout=120)

    vuln_patterns = [
        (r"VULNERABLE", Severity.HIGH, "nmap vuln script detected vulnerability"),
        (r"CVE-\d{4}-\d+", Severity.HIGH, "CVE referenced in nmap scan"),
        (r"XSS|cross.site scripting", Severity.HIGH, "XSS detected by nmap script"),
        (r"SQL injection|sqli", Severity.CRITICAL, "SQL injection detected by nmap script"),
    ]

    seen = set()
    for pattern, severity, title in vuln_patterns:
        for match in re.finditer(pattern, out, re.IGNORECASE):
            snippet = out[max(0, match.start()-80):match.end()+80].strip()
            key = snippet[:60]
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                id=_next_id(),
                severity=severity,
                category="network",
                title=title,
                description=f"nmap NSE vuln script found issue on {host}.",
                file_path=None, line_number=None,
                evidence=snippet[:300],
                fix_suggestion="Investigate the specific CVE or vulnerability class and apply vendor patch.",
                auto_fixable=False,
            ))
            if len(findings) >= 5:
                break

    return findings


# ── HTTP security headers ──────────────────────────────────────

def _check_headers(url: str) -> list[Finding]:
    findings = []
    out = _run(["curl", "-sI", "--max-time", "10", "--location", url], timeout=15)
    if not out or "timeout" in out or "error" in out.lower():
        return findings

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": (
            Severity.HIGH,
            "Missing HSTS header",
            "HSTS not set — browsers won't enforce HTTPS. Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ),
        "Content-Security-Policy": (
            Severity.HIGH,
            "Missing Content-Security-Policy",
            "No CSP header — XSS attacks can execute arbitrary scripts. Define a strict CSP policy.",
        ),
        "X-Frame-Options": (
            Severity.MEDIUM,
            "Missing X-Frame-Options",
            "No clickjacking protection. Add: X-Frame-Options: DENY or use CSP frame-ancestors.",
        ),
        "X-Content-Type-Options": (
            Severity.MEDIUM,
            "Missing X-Content-Type-Options",
            "MIME sniffing enabled. Add: X-Content-Type-Options: nosniff",
        ),
        "Permissions-Policy": (
            Severity.LOW,
            "Missing Permissions-Policy",
            "No Permissions-Policy — camera/mic/geolocation APIs unrestricted. Add Permissions-Policy header.",
        ),
        "Referrer-Policy": (
            Severity.LOW,
            "Missing Referrer-Policy",
            "Referrer data may leak to third parties. Add: Referrer-Policy: strict-origin-when-cross-origin",
        ),
    }

    headers_lower = out.lower()
    for header, (severity, title, fix) in REQUIRED_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append(Finding(
                id=_next_id(),
                severity=severity,
                category="network",
                title=title,
                description=f"Security header '{header}' not present in HTTP response from {url}.",
                file_path=None, line_number=None,
                evidence=f"Header '{header}' absent from response",
                fix_suggestion=fix,
                auto_fixable=False,
            ))

    # Check if server header exposes version
    server_match = re.search(r"^server:\s*(.+)$", out, re.IGNORECASE | re.MULTILINE)
    if server_match:
        server_val = server_match.group(1).strip()
        if re.search(r"\d+\.\d+", server_val):
            findings.append(Finding(
                id=_next_id(),
                severity=Severity.LOW,
                category="network",
                title="Server version disclosure",
                description=f"Server header exposes version info: '{server_val}'. Helps attackers identify CVEs.",
                file_path=None, line_number=None,
                evidence=f"Server: {server_val}",
                fix_suggestion="Suppress server version: ServerTokens Prod (Apache) or server_tokens off (nginx).",
                auto_fixable=False,
            ))

    return findings


# ── TLS / SSL ──────────────────────────────────────────────────

def _check_tls(host: str) -> list[Finding]:
    findings = []
    out = _run(["openssl", "s_client", "-connect", f"{host}:443", "-brief"], timeout=10)

    if "unable to load" in out or "Connection refused" in out or "connect: " in out.lower():
        return findings

    # Cert expiry
    cert_chain = _run(["openssl", "s_client", "-connect", f"{host}:443", "-showcerts"], timeout=10)
    cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert_chain, re.DOTALL)
    cert_out = _run(["openssl", "x509", "-noout", "-dates"], timeout=10, input_text=cert_match.group(0) if cert_match else None)
    expiry_match = re.search(r"notAfter=(.*)", cert_out)
    if expiry_match:
        import datetime
        try:
            expiry_str = expiry_match.group(1).strip()
            expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append(Finding(
                    id=_next_id(), severity=Severity.CRITICAL,
                    category="network", title="TLS certificate expired",
                    description=f"Certificate expired {abs(days_left)} days ago. All browsers show security warning.",
                    file_path=None, line_number=None,
                    evidence=f"notAfter={expiry_str}",
                    fix_suggestion="Renew certificate immediately. Use Let's Encrypt for free auto-renewal.",
                    auto_fixable=False,
                ))
            elif days_left < 30:
                findings.append(Finding(
                    id=_next_id(), severity=Severity.HIGH,
                    category="network", title=f"TLS certificate expires in {days_left} days",
                    description="Certificate expiring soon — service will break for all users.",
                    file_path=None, line_number=None,
                    evidence=f"notAfter={expiry_str}",
                    fix_suggestion="Renew certificate now. Use Let's Encrypt + certbot for auto-renewal.",
                    auto_fixable=False,
                ))
        except Exception:
            pass

    # Weak TLS versions
    for tls_ver, label in [("tls1", "TLS 1.0"), ("tls1_1", "TLS 1.1")]:
        ver_out = _run(["openssl", "s_client", f"-{tls_ver}", "-connect", f"{host}:443"], timeout=8)
        if "Cipher is" in ver_out or "Protocol  : " in ver_out:
            findings.append(Finding(
                id=_next_id(), severity=Severity.HIGH,
                category="network", title=f"{label} supported (deprecated)",
                description=f"{label} is deprecated and has known vulnerabilities (POODLE, BEAST). Disable it.",
                file_path=None, line_number=None,
                evidence=f"{label} handshake succeeded",
                fix_suggestion=f"Disable {label} in server config. Support only TLS 1.2 and 1.3.",
                auto_fixable=False,
            ))

    return findings


# ── DNS ───────────────────────────────────────────────────────

def _check_dns(host: str) -> list[Finding]:
    findings = []

    # SPF record
    spf_out = _run(["dig", "+short", "TXT", host], timeout=10)
    if "v=spf1" not in spf_out:
        findings.append(Finding(
            id=_next_id(), severity=Severity.MEDIUM,
            category="network", title="Missing SPF DNS record",
            description=f"No SPF record found for {host}. Attackers can spoof email from this domain.",
            file_path=None, line_number=None,
            evidence="No TXT record containing v=spf1",
            fix_suggestion='Add SPF record: v=spf1 include:_spf.yourmailprovider.com ~all',
            auto_fixable=False,
        ))

    # DMARC
    dmarc_out = _run(["dig", "+short", "TXT", f"_dmarc.{host}"], timeout=10)
    if "v=DMARC1" not in dmarc_out:
        findings.append(Finding(
            id=_next_id(), severity=Severity.MEDIUM,
            category="network", title="Missing DMARC DNS record",
            description=f"No DMARC record for {host}. Email spoofing attacks can go unreported.",
            file_path=None, line_number=None,
            evidence="No _dmarc TXT record found",
            fix_suggestion='Add DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com',
            auto_fixable=False,
        ))

    # Zone transfer attempt
    ns_out = _run(["dig", "+short", "NS", host], timeout=10)
    ns_servers = [line.strip() for line in ns_out.splitlines() if line.strip()]
    for ns in ns_servers[:2]:
        axfr_out = _run(["dig", f"@{ns}", host, "AXFR"], timeout=10)
        if "Transfer failed" not in axfr_out and len(axfr_out) > 200 and "IN" in axfr_out:
            findings.append(Finding(
                id=_next_id(), severity=Severity.CRITICAL,
                category="network", title="DNS zone transfer allowed",
                description=f"Nameserver {ns} allows AXFR zone transfer — exposes all DNS records.",
                file_path=None, line_number=None,
                evidence=axfr_out[:300],
                fix_suggestion="Restrict AXFR to authorized secondary nameservers only.",
                auto_fixable=False,
            ))
            break

    return findings


# ── nikto ────────────────────────────────────────────────────

def _nikto(url: str) -> list[Finding]:
    findings = []
    out = _run(["nikto", "-h", url, "-maxtime", "60", "-nointeractive"], timeout=75)

    for line in out.splitlines():
        if line.startswith("+") and ("OSVDB" in line or "vulnerable" in line.lower() or "CVE" in line):
            severity = Severity.HIGH if "CVE" in line or "inject" in line.lower() else Severity.MEDIUM
            findings.append(Finding(
                id=_next_id(), severity=severity,
                category="network", title="nikto: " + line[2:60].strip(),
                description=f"nikto web scanner finding on {url}.",
                file_path=None, line_number=None,
                evidence=line.strip()[:300],
                fix_suggestion="Investigate and remediate the specific issue flagged by nikto.",
                auto_fixable=False,
            ))
        if len(findings) >= 8:
            break

    return findings


# ── gobuster dir enum ─────────────────────────────────────────

def _gobuster(url: str) -> list[Finding]:
    # Use a small built-in wordlist — no external file needed
    if not shutil.which("gobuster"):
        return []
    # Try to find any wordlist
    import os
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/opt/homebrew/share/wordlists/dirb/common.txt",
        "/usr/local/share/dirb/wordlists/common.txt",
    ]
    wl = next((c for c in candidates if os.path.exists(c)), None)
    if not wl:
        # Write a minimal built-in wordlist
        wl = "/tmp/cosentinel_wordlist.txt"
        with open(wl, "w") as f:
            f.write("\n".join([
                "admin", "login", "dashboard", "api", "config", "backup",
                "test", "dev", "staging", ".env", ".git", "phpinfo.php",
                "wp-admin", "wp-config.php", "admin.php", "panel",
                "console", "debug", "actuator", "metrics", "health",
                "swagger", "api-docs", "graphql", "uploads", "files",
            ]))

    findings = []
    out = _run(["gobuster", "dir", "-u", url, "-w", wl, "-q", "-t", "20", "--timeout", "5s"], timeout=60)

    sensitive = re.compile(r"(admin|login|config|backup|\.env|\.git|debug|console|phpinfo|actuator|swagger|graphql)", re.I)
    for line in out.splitlines():
        if "(Status: 200)" in line or "(Status: 301)" in line or "(Status: 302)" in line:
            path = line.split()[0]
            if sensitive.search(path):
                findings.append(Finding(
                    id=_next_id(), severity=Severity.HIGH,
                    category="network", title=f"Sensitive path exposed: {path}",
                    description=f"Sensitive endpoint {path} is publicly accessible on {url}.",
                    file_path=None, line_number=None,
                    evidence=line.strip(),
                    fix_suggestion=f"Restrict access to {path} with authentication or remove if unused.",
                    auto_fixable=False,
                ))
            elif len(findings) < 5:
                findings.append(Finding(
                    id=_next_id(), severity=Severity.LOW,
                    category="network", title=f"Discovered path: {path}",
                    description=f"Directory enumeration found accessible path {path} on {url}.",
                    file_path=None, line_number=None,
                    evidence=line.strip(),
                    fix_suggestion="Review if this path should be publicly accessible.",
                    auto_fixable=False,
                ))

    return findings


# ── nuclei (info / misconfig only) ─────────────────────────────

def _nuclei(url: str) -> list[Finding]:
    findings = []
    # info + misconfig tags only; no exploit templates; rate limited
    out = _run(
        [
            "nuclei",
            "-u",
            url,
            "-tags",
            "info,misconfig,exposure,tech",
            "-severity",
            "info,low,medium,high,critical",
            "-silent",
            "-no-color",
            "-rate-limit",
            "15",
            "-timeout",
            "8",
            "-max-host-error",
            "5",
        ],
        timeout=90,
    )

    seen: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("[") and "INF]" in line:
            continue
        key = line[:80]
        if key in seen:
            continue
        seen.add(key)
        lower = line.lower()
        severity = Severity.MEDIUM
        if "critical" in lower or "cve-" in lower:
            severity = Severity.HIGH
        elif "info" in lower:
            severity = Severity.INFO
        findings.append(
            Finding(
                id=_next_id(), severity=severity,
                category="network", title="nuclei: " + line[:80],
                description=f"nuclei passive template match on {url}.",
                file_path=None, line_number=None,
                evidence=line[:300],
                fix_suggestion="Review the nuclei finding and harden the exposed service or header.",
                auto_fixable=False,
            )
        )
        if len(findings) >= 10:
            break
    return findings


# ── helpers ───────────────────────────────────────────────────

def _extract_port_line(text: str, port: str) -> str:
    for line in text.splitlines():
        if f"{port}/tcp" in line:
            return line.strip()[:200]
    return f"port {port}/tcp open"


def _extract_grep(text: str, pattern: str) -> str:
    for line in text.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            return line.strip()[:200]
    return ""


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    results = scan_network(target)
    print(f"network.py self-check OK: {len(results)} findings on {target}")
    for f in results[:5]:
        print(f"  [{f.severity.value}] {f.title}")
