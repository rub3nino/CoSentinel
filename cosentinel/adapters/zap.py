"""OWASP ZAP adapter — full active web-application scan.

ZAP is what gets us closest to a human web pentester working through an app:
it spiders the site and then *actively attacks* every parameter and form it
finds (SQLi, XSS, path traversal, injection, insecure headers, …). That is an
aggressive act, so the adapter's window starts at AGGRESSIVE and it never runs
in a SAFE scan.

We drive the packaged `zap-full-scan.py` (active scan) and parse its JSON
report. As with OpenVAS, the JSON *parser* is unit-tested here; the exact local
invocation of zap-full-scan.py (native vs. docker, where it writes the report)
depends on your ZAP install and should be validated against a running ZAP.
"""

from __future__ import annotations

import json
import os
import re
import shlex

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult, Runner
from .base import Adapter, PlannedCommand, register

_REPORT = "/tmp/cosentinel-zap.json"
# ZAP riskcode -> our Severity. ZAP tops out at High; it has no "critical".
_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_TAG_RE = re.compile(r"<[^>]+>")


def _zap_cmd() -> list[str]:
    """The ZAP launcher. Defaults to the Docker packaged-scan `zap-full-scan.py`;
    override with COSENTINEL_ZAP to run ZAP natively (e.g. scripts/zap-native.sh),
    which is what reaches a Tailscale/host-only target Docker cannot. The override
    still receives the same `-t URL -J report -I` flags."""
    return shlex.split(os.environ.get("COSENTINEL_ZAP", "")) or ["zap-full-scan.py"]


def _clean(html: str) -> str:
    return _TAG_RE.sub("", html or "").strip()


@register
class ZapAdapter(Adapter):
    name = "zap"
    requires_tool = "zap-full-scan.py"
    runs_on = "scanner"
    min_intensity = Intensity.AGGRESSIVE   # active attack — never in a SAFE scan
    max_intensity = Intensity.AGGRESSIVE

    def available(self, runner: Runner) -> bool:
        # Honor a COSENTINEL_ZAP override (e.g. the native shim): check its actual
        # launcher exists, not the literal zap-full-scan.py.
        return runner.which(_zap_cmd()[0])

    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        return [
            PlannedCommand(argv=["rm", "-f", _REPORT], timeout=30, label="clear old report"),
            PlannedCommand(
                argv=[*_zap_cmd(), "-t", target.web_target, "-J", _REPORT, "-I"],
                timeout=3600, label="ZAP full active scan",
            ),
            PlannedCommand(argv=["cat", _REPORT], timeout=30, label="read report"),
        ]

    def parse(
        self, results: list[CommandResult], target: Target, intensity: Intensity
    ) -> list[Finding]:
        raw = results[-1].stdout if results else ""
        if not raw.strip():
            scan = results[-2] if len(results) >= 2 else None
            detail = (scan.stderr.strip() if scan and scan.stderr else "") or \
                     "ZAP did not produce a report"
            return [self._info("ZAP produced no report", detail, target)]
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            return [self._info("could not parse ZAP report", str(e), target)]

        findings: list[Finding] = []
        for site in data.get("site", []) or []:
            site_name = site.get("@name") or target.web_target
            for alert in site.get("alerts", []) or []:
                sev = _RISK.get(str(alert.get("riskcode", "0")), Severity.INFO)
                instances = alert.get("instances") or []
                where = (instances[0].get("uri") if instances else "") or site_name

                refs: list[str] = []
                cwe = str(alert.get("cweid", "")).strip()
                if cwe and cwe not in ("", "-1", "0"):
                    refs.append(f"CWE-{cwe}")
                for r in _clean(alert.get("reference", "")).split("\n"):
                    if r.strip():
                        refs.append(r.strip())

                findings.append(Finding(
                    source=self.name, target=target.id, severity=sev,
                    category=Category.WEB,
                    title=alert.get("alert") or alert.get("name") or "ZAP alert",
                    resource=where,
                    description=_clean(alert.get("desc", ""))[:1000],
                    remediation=_clean(alert.get("solution", "")) or
                                "Review and fix per the referenced guidance.",
                    references=refs,
                    raw={"pluginid": alert.get("pluginid"),
                         "confidence": alert.get("confidence"),
                         "count": len(instances)},
                ))

        if not findings:
            findings.append(self._info("ZAP: no alerts", target.web_target, target))
        return findings

    @staticmethod
    def _info(title: str, detail: str, target: Target) -> Finding:
        return Finding(source="zap", target=target.id, severity=Severity.INFO,
                       category=Category.INFO, title=title, description=detail,
                       resource=target.web_target)
