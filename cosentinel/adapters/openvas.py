"""OpenVAS / Greenbone (GVM) adapter — deep vulnerability scanning.

Unlike the other adapters, OpenVAS is not a binary you run: it is a *service*
(Greenbone/GVM) you talk to over the GMP protocol with `gvm-cli`. So this
adapter overrides `scan()` to drive the full task lifecycle against a running
GVM instance: create target -> create task -> start -> poll until done ->
fetch report -> normalize results into findings.

Connection comes from the environment (never from the config file, so GVM
credentials are not written to disk):

    GVM_SOCKETPATH   unix socket (e.g. /run/gvmd/gvmd.sock)   -- preferred, or
    GVM_HOST / GVM_PORT   TLS endpoint (default 127.0.0.1:9390)
    GVM_USERNAME / GVM_PASSWORD
    GVM_SCAN_CONFIG  scan config id   (default: "Full and fast")
    GVM_SCANNER      scanner id       (default: OpenVAS default scanner)
    GVM_MAX_WAIT     seconds to wait for the scan (default 3600)
    GVM_CLI          override the gvm-cli command when it must run elsewhere,
                     e.g. inside the dockerized GVM:
                       "docker compose -f /path/compose.yaml exec -T gvm-tools gvm-cli"

NOTE: the GMP report XML *parser* is unit-tested; the live task lifecycle
requires a running GVM instance and must be validated against one before it is
trusted. Without GVM, the adapter reports that cleanly instead of pretending.
"""

from __future__ import annotations

import os
import shlex
import time
import xml.etree.ElementTree as ET

from ..core.findings import Category, Finding, Severity
from ..core.profiles import Intensity
from ..core.scope import Target
from ..transport.ssh import CommandResult, Runner
from .base import Adapter, PlannedCommand, register

# Well-known GVM UUIDs (overridable via env).
_DEFAULT_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"   # Full and fast
_DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"        # OpenVAS default

_THREAT = {
    "Log": Severity.INFO,
    "Debug": Severity.INFO,
    "False Positive": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}


def _cli() -> list[str]:
    """The gvm-cli command, overridable via GVM_CLI (e.g. to run it inside the
    GVM container through `docker compose exec`)."""
    return shlex.split(os.environ.get("GVM_CLI", "gvm-cli")) or ["gvm-cli"]


def _connection() -> list[str]:
    """gvm-cli auth + connection args from the environment."""
    argv: list[str] = []
    if os.environ.get("GVM_USERNAME"):
        argv += ["--gmp-username", os.environ["GVM_USERNAME"]]
    if os.environ.get("GVM_PASSWORD"):
        argv += ["--gmp-password", os.environ["GVM_PASSWORD"]]
    sock = os.environ.get("GVM_SOCKETPATH")
    if sock:
        argv += ["socket", "--socketpath", sock]
    else:
        argv += ["tls",
                 "--hostname", os.environ.get("GVM_HOST", "127.0.0.1"),
                 "--port", os.environ.get("GVM_PORT", "9390")]
    return argv


def _severity_of(result: ET.Element) -> Severity:
    threat = (result.findtext("threat") or "").strip()
    if threat in _THREAT:
        return _THREAT[threat]
    try:
        cvss = float(result.findtext("severity") or "0")
    except ValueError:
        cvss = 0.0
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss > 0.0:
        return Severity.LOW
    return Severity.INFO


@register
class OpenvasAdapter(Adapter):
    name = "openvas"
    requires_tool = "gvm-cli"
    runs_on = "scanner"
    max_intensity = Intensity.SAFE

    def available(self, runner: Runner) -> bool:
        # Honor a GVM_CLI override (e.g. "docker … exec … gvm-cli"): check that
        # its actual launcher (docker/gvm-cli/…) exists, not the literal gvm-cli.
        return runner.which(_cli()[0])

    # -- dry-run visibility: a representative view of the lifecycle ---------
    def plan(self, target: Target, intensity: Intensity) -> list[PlannedCommand]:
        base = [*_cli(), *_connection(), "--xml"]
        host = target.host
        return [
            PlannedCommand(argv=[*base, "<get_version/>"], label="check GVM connectivity"),
            PlannedCommand(argv=[*base, f"<create_target><name>cosentinel-{host}</name>"
                                         f"<hosts>{host}</hosts></create_target>"],
                           label="create target"),
            PlannedCommand(argv=[*base, "<create_task>…<config/><target/><scanner/></create_task>"],
                           label="create task"),
            PlannedCommand(argv=[*base, "<start_task task_id='…'/>"], label="start + poll until done"),
            PlannedCommand(argv=[*base, "<get_reports report_id='…' details='1'/>"],
                           label="fetch + parse report"),
        ]

    # -- the real lifecycle ------------------------------------------------
    def scan(self, runner: Runner, target: Target, intensity: Intensity) -> list[Finding]:
        base = [*_cli(), *_connection(), "--xml"]

        def gmp(xml: str, timeout: int = 180) -> CommandResult:
            return runner.run([*base, xml], timeout=timeout)

        ver = gmp("<get_version/>", 60)
        if not ver.ok or "<version>" not in ver.stdout:
            return [self._info("GVM not reachable",
                               (ver.stderr or ver.stdout or "no response from gvm-cli").strip()[:300],
                               target)]

        host = target.host
        scan_config = os.environ.get("GVM_SCAN_CONFIG", _DEFAULT_SCAN_CONFIG)
        scanner = os.environ.get("GVM_SCANNER", _DEFAULT_SCANNER)
        tag = str(int(time.time()))

        tid = _attr(gmp(f"<create_target><name>cosentinel-{host}-{tag}</name>"
                        f"<hosts>{host}</hosts></create_target>"), "id")
        if not tid:
            return [self._info("could not create GVM target", "create_target failed", target)]

        task_id = _attr(gmp(f"<create_task><name>cosentinel-{host}-{tag}</name>"
                            f"<config id='{scan_config}'/><target id='{tid}'/>"
                            f"<scanner id='{scanner}'/></create_task>"), "id")
        if not task_id:
            return [self._info("could not create GVM task", "create_task failed", target)]

        report_id = _text(gmp(f"<start_task task_id='{task_id}'/>"), "report_id")
        if not report_id:
            return [self._info("could not start GVM task", "start_task failed", target)]

        # Poll until the task finishes (or we hit the wait budget).
        max_wait = int(os.environ.get("GVM_MAX_WAIT", "3600"))
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            status = _status(gmp(f"<get_tasks task_id='{task_id}'/>", 120))
            if status in ("Done", "Stopped", "Interrupted"):
                break
            time.sleep(15)
        else:
            return [self._info("GVM scan timed out", f"still running after {max_wait}s", target)]

        report = gmp(f"<get_reports report_id='{report_id}' details='1'/>", 300)
        return self.parse([report], target, intensity)

    # -- report parsing (unit-tested) --------------------------------------
    def parse(self, results: list[CommandResult], target: Target, intensity: Intensity) -> list[Finding]:
        xml = results[-1].stdout if results else ""
        if not xml.strip():
            return [self._info("GVM returned an empty report", "", target)]
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            return [self._info("could not parse GVM report", str(e), target)]

        findings: list[Finding] = []
        for res in root.iter("result"):
            nvt = res.find("nvt")
            name = (res.findtext("name") or (nvt.findtext("name") if nvt is not None else "") or
                    "OpenVAS finding")
            rhost = (res.findtext("host") or "").strip()
            port = (res.findtext("port") or "").strip()
            sev = _severity_of(res)
            refs = _refs(nvt)
            solution = _tag_value(nvt, "solution") if nvt is not None else ""
            findings.append(Finding(
                source=self.name, target=target.id, severity=sev,
                category=Category.VULNERABILITY, title=name.strip(),
                resource=f"{rhost} {port}".strip(),
                description=(res.findtext("description") or "").strip()[:1000],
                remediation=solution or "Patch/upgrade the affected component or restrict access.",
                references=refs,
                raw={"oid": nvt.get("oid") if nvt is not None else None},
            ))

        if not findings:
            findings.append(self._info("OpenVAS: no results in report", target.host, target))
        return findings

    @staticmethod
    def _info(title: str, detail: str, target: Target) -> Finding:
        return Finding(source="openvas", target=target.id, severity=Severity.INFO,
                       category=Category.INFO, title=title, description=detail)


# -- small GMP-XML helpers -------------------------------------------------
def _attr(res: CommandResult, name: str) -> str:
    try:
        return ET.fromstring(res.stdout).get(name, "")
    except (ET.ParseError, TypeError):
        return ""


def _text(res: CommandResult, tag: str) -> str:
    try:
        return (ET.fromstring(res.stdout).findtext(tag) or "").strip()
    except (ET.ParseError, TypeError):
        return ""


def _status(res: CommandResult) -> str:
    try:
        root = ET.fromstring(res.stdout)
        task = root.find("task")
        return (task.findtext("status") if task is not None else "") or ""
    except (ET.ParseError, TypeError):
        return ""


def _refs(nvt: ET.Element | None) -> list[str]:
    if nvt is None:
        return []
    out: list[str] = []
    cve = nvt.findtext("cve")
    if cve and cve.upper() != "NOCVE":
        out += [c.strip() for c in cve.split(",") if c.strip()]
    refs = nvt.find("refs")
    if refs is not None:
        for ref in refs.findall("ref"):
            if ref.get("type") == "cve" and ref.get("id"):
                out.append(ref.get("id"))
    # de-dup, keep order
    seen: set[str] = set()
    return [r for r in out if not (r in seen or seen.add(r))]


def _tag_value(nvt: ET.Element, key: str) -> str:
    tags = nvt.findtext("tags") or ""
    for part in tags.split("|"):
        if part.startswith(key + "="):
            return part[len(key) + 1:].strip()
    return ""
