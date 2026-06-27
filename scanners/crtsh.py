import re
from urllib.parse import urlparse

import requests

from models import Finding, Severity

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
SENSITIVE = re.compile(r"(?i)(admin|staging|stage|dev|test|internal|intranet|api|backup|jenkins|grafana|kibana|vault|redis|mysql|mongo|elastic|debug|beta|preview|legacy|old|private|secret|vpn|mail|smtp|ftp|db|postgres|grafana|gitlab|jira|confluence)")


def _root_domain(host: str) -> str:
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # ponytail: naive eTLD+1 — good enough for hackathon crt.sh queries
    return ".".join(parts[-2:])


def collect_domains(target_findings: list, repo_url: str = "", live_target: str = "") -> list[str]:
    domains: set[str] = set()
    for finding in target_findings:
        if getattr(finding, "category", "") != "target":
            continue
        raw = finding.title.split(": ", 1)[-1]
        host = urlparse(raw if "://" in raw else f"https://{raw}").hostname
        if host:
            domains.add(_root_domain(host))
    if live_target:
        host = urlparse(live_target if "://" in live_target else f"https://{live_target}").hostname
        if host:
            domains.add(_root_domain(host))
    return sorted(domains)[:5]


def scan_crtsh(domains: list[str]) -> list[Finding]:
    """Passive subdomain discovery via crt.sh certificate transparency logs."""
    if not domains:
        return []

    findings: list[Finding] = []
    counter = 0

    for domain in domains:
        try:
            resp = requests.get(CRTSH_URL.format(domain=domain), timeout=20)
            if resp.status_code != 200:
                continue
            rows = resp.json()
        except Exception:
            continue

        names: set[str] = set()
        for row in rows[:200]:
            value = row.get("name_value") or ""
            for part in value.split("\n"):
                part = part.strip().lower().removeprefix("*.")
                if part and domain in part:
                    names.add(part)

        if not names:
            continue

        sensitive = sorted(n for n in names if SENSITIVE.search(n))[:8]
        counter += 1
        if sensitive:
            findings.append(
                Finding(
                    id=f"CRT-{counter:03d}",
                    severity=Severity.HIGH,
                    category="crtsh",
                    title=f"Sensitive subdomains in CT logs for {domain}",
                    description="Certificate Transparency exposed hostnames that may expand the attack surface.",
                    file_path=None,
                    line_number=None,
                    evidence=", ".join(sensitive[:6]),
                    fix_suggestion="Review whether these hosts should be public; remove unused DNS and certificates.",
                    auto_fixable=False,
                )
            )
        elif len(names) >= 5:
            counter += 1
            sample = ", ".join(sorted(names)[:6])
            findings.append(
                Finding(
                    id=f"CRT-{counter:03d}",
                    severity=Severity.INFO,
                    category="crtsh",
                    title=f"Subdomain inventory for {domain} ({len(names)} hosts)",
                    description="Passive CT log enumeration found additional hostnames for this domain.",
                    file_path=None,
                    line_number=None,
                    evidence=sample,
                    fix_suggestion="Validate DNS inventory and decommission unused subdomains.",
                    auto_fixable=False,
                )
            )

    return findings


if __name__ == "__main__":
    # offline self-check for helpers only
    assert _root_domain("api.staging.example.com") == "example.com"
    assert SENSITIVE.search("admin.example.com")
    print("crtsh.py self-check OK")
