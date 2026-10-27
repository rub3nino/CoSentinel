"""ffuf adapter — content & endpoint discovery.

Before attacking an app, a human tester maps its hidden surface: admin panels,
backups, `.git`, `.env`, old endpoints. ffuf brute-forces paths from a wordlist
and reports what responds. That is a lot of active requests, so the window is
AGGRESSIVE-only.

Needs a wordlist: set COSENTINEL_WORDLIST, or install one of the common defaults
below (e.g. SecLists / dirb). The JSON-report parser is unit-tested.
"""

from __future__ import annotations

import json
import os

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult
from .base import Adapter, PlannedCommand, register

_REPORT = "/tmp/cosentinel-ffuf.json"
_WORDLIST_ENV = "COSENTINEL_WORDLIST"
_WORDLIST_DEFAULTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
)
# Paths that are interesting enough to raise above a plain "it exists" note.
_SENSITIVE = (".git", ".env", ".svn", "backup", ".bak", ".sql", "config", "admin",
              "phpinfo", "wp-admin", ".htpasswd", "id_rsa", "dump")


def _wordlist() -> str | None:
    env = os.environ.get(_WORDLIST_ENV)
    if env and os.path.exists(env):
        return env
    return next((p for p in _WORDLIST_DEFAULTS if os.path.exists(p)), None)


@register
class FfufAdapter(Adapter):
    name = "ffuf"
    requires_tool = "ffuf"
    runs_on = "scanner"
    min_intensity = Intensity.AGGRESSIVE   # heavy request volume — never in a SAFE scan
    max_intensity = Intensity.AGGRESSIVE

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        wl = _wordlist() or _WORDLIST_DEFAULTS[0]
        url = target.web_target.rstrip("/") + "/FUZZ"
        return [
            PlannedCommand(argv=["rm", "-f", _REPORT], timeout=30, label="clear old report"),
            PlannedCommand(
                argv=["ffuf", "-u", url, "-w", wl,
                      "-mc", "200,204,301,302,307,401,403,405",
                      "-of", "json", "-o", _REPORT, "-s"],
                timeout=1800, label="ffuf content discovery",
            ),
            PlannedCommand(argv=["cat", _REPORT], timeout=30, label="read report"),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        raw = results[-1].stdout if results else ""
        if not raw.strip():
            scan = results[-2] if len(results) >= 2 else None
            err = (scan.stderr.lower() if scan and scan.stderr else "")
            if "wordlist" in err or _wordlist() is None:
                return [self._info(
                    "ffuf: no wordlist available",
                    f"Set {_WORDLIST_ENV} or install a wordlist (SecLists/dirb).", target)]
            return [self._info("ffuf produced no report",
                               (scan.stderr.strip() if scan else "") or "", target)]
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return [self._info("could not parse ffuf report", str(e), target)]

        findings: list[Finding] = []
        for r in data.get("results", []) or []:
            url = r.get("url") or r.get("input", {}).get("FUZZ", "")
            status = r.get("status", 0)
            sensitive = any(s in url.lower() for s in _SENSITIVE)
            if sensitive:
                sev = Severity.MEDIUM
            elif status in (200, 204, 401, 403):
                sev = Severity.LOW
            else:
                sev = Severity.INFO
            findings.append(Finding(
                source=self.name, target=target.id, severity=sev,
                category=Category.WEB,
                title=f"Discovered endpoint: {url} ({status})",
                resource=url,
                description=f"Path responded with HTTP {status}, length {r.get('length', '?')}."
                            + (" Path name looks sensitive." if sensitive else ""),
                remediation="Confirm this path is meant to be reachable; remove or protect "
                            "backups, VCS/config files and admin panels.",
                raw={"status": status, "length": r.get("length")},
            ))

        if not findings:
            findings.append(self._info("ffuf: no paths discovered", target.web_target, target))
        return findings

    @staticmethod
    def _info(title: str, detail: str, target: Target) -> Finding:
        return Finding(source="ffuf", target=target.id, severity=Severity.INFO,
                       category=Category.INFO, title=title, description=detail,
                       resource=target.web_target)
