"""Passive OSINT via Internet Archive CDX — historical URLs for declared domains."""

from __future__ import annotations

import re

import requests

from models import Finding, Severity

CDX_URL = "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=120"
SENSITIVE_PATH = re.compile(
    r"(?i)(/admin|/debug|/actuator|/\.env|/backup|/wp-admin|/phpmyadmin|"
    r"/config\.|/api/internal|/swagger|/graphql|/shell|/upload|/console|"
    r"/manage|/jenkins|/grafana|/\.git|/trace|/metrics|/status|/phpinfo)"
)


def scan_wayback(domains: list[str]) -> list[Finding]:
    """Query Wayback CDX for archived sensitive paths. Passive — no probing of live hosts."""
    if not domains:
        return []

    findings: list[Finding] = []
    counter = 0

    for domain in domains:
        try:
            resp = requests.get(CDX_URL.format(domain=domain), timeout=25)
            if resp.status_code != 200:
                continue
            rows = resp.json()
        except Exception:
            continue

        if not rows or len(rows) < 2:
            continue

        hits: list[str] = []
        for row in rows[1:]:
            if not row:
                continue
            url = row[0] if isinstance(row, list) else str(row)
            if SENSITIVE_PATH.search(url):
                hits.append(url)
            if len(hits) >= 8:
                break

        if not hits:
            continue

        counter += 1
        findings.append(
            Finding(
                id=f"WB-{counter:03d}",
                severity=Severity.HIGH,
                category="wayback",
                title=f"Archived sensitive paths for {domain}",
                description="Internet Archive captured URLs that suggest previously exposed admin or config endpoints.",
                file_path=None,
                line_number=None,
                evidence=" · ".join(hits[:5])[:400],
                fix_suggestion="Verify these paths are removed or protected; rotate credentials if they were ever exposed.",
                auto_fixable=False,
            )
        )

    return findings


if __name__ == "__main__":
    from scanners.crtsh import collect_domains
    from models import Finding as F

    tgt = F(
        "TGT-001",
        Severity.INFO,
        "target",
        "Deploy target declared: https://example.com",
        "target",
        None,
        None,
        "https://example.com",
        fix_suggestion="scope",
        auto_fixable=False,
    )
    domains = collect_domains([tgt], "", "")
    assert domains == ["example.com"]
    print("wayback.py self-check OK", domains)
