import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import config
from models import Finding, Severity

SEVERITY = {
    "Run as root": Severity.MEDIUM,
    "Privileged mode hint": Severity.HIGH,
    "Secrets in ENV": Severity.HIGH,
    "Latest tag": Severity.MEDIUM,
    "Secrets in env": Severity.HIGH,
    "Pull request write": Severity.MEDIUM,
    "Untrusted input in run": Severity.HIGH,
    "Real secret in example": Severity.HIGH,
    "Privileged Container": Severity.HIGH,
    "Exposed on all interfaces": Severity.HIGH,
}

FIXES = {
    "Run as root": "Add a non-root USER directive after installing dependencies",
    "Privileged mode hint": "Drop --privileged; grant only the specific capabilities needed",
    "Secrets in ENV": "Pass secrets at runtime via secret stores or --env-file, never bake into the image",
    "Latest tag": "Pin the base image to an explicit version digest for reproducible builds",
    "Secrets in env": "Reference GitHub Actions secrets via secrets context with least privilege",
    "Pull request write": "Use read-only permissions; grant write only on the specific job that needs it",
    "Untrusted input in run": "Never interpolate ${{ github.event.* }} into run; pass via env and quote",
    "Real secret in example": "Replace with a placeholder like CHANGE_ME; never commit real values",
    "Privileged Container": "Remove 'privileged: true'; use cap_add for the specific capability",
    "Exposed on all interfaces": "Bind sensitive ports to 127.0.0.1 instead of 0.0.0.0",
}


def _config_type(rel_path: str) -> str | None:
    name = os.path.basename(rel_path)
    p = rel_path.replace("\\", "/")
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "Dockerfile"
    if ".github/workflows/" in p and (name.endswith(".yml") or name.endswith(".yaml")):
        return ".github/workflows"
    if name in (".env.example", ".env.sample", ".env.test"):
        return ".env.example"
    if name in ("docker-compose.yml", "docker-compose.yaml"):
        return "docker-compose"
    if name in ("nginx.conf", "apache2.conf", "httpd.conf"):
        return "webserver"
    if (("k8s/" in p) or ("kubernetes/" in p) or ("helm/" in p)) and name.endswith(".yaml"):
        return "kubernetes"
    return None


def scan_config(local_path: str, all_files: list[str]) -> list[Finding]:
    targets = [(f, _config_type(f)) for f in all_files]
    targets = [(f, t) for f, t in targets if t]

    counter = [0]
    lock = threading.Lock()
    findings: list[Finding] = []

    def new_finding(name, ctype, rel_path, lineno, line):
        with lock:
            counter[0] += 1
            fid = f"CFG-{counter[0]:03d}"
        return Finding(
            id=fid,
            severity=SEVERITY.get(name, Severity.LOW),
            category="config",
            title=f"{ctype}: {name}",
            description=RISK_DESCRIPTIONS.get(name, name),
            file_path=rel_path,
            line_number=lineno,
            evidence=line.strip()[:200],
            fix_suggestion=FIXES.get(name, "Review this configuration against security best practices"),
            auto_fixable=False,
        )

    def scan_file(item) -> list[Finding]:
        rel_path, ctype = item
        patterns = config.DANGEROUS_CONFIG_PATTERNS.get(ctype, {})
        compiled = [(name, re.compile(rx)) for name, rx in patterns.items()]
        abs_path = os.path.join(local_path, rel_path)
        out: list[Finding] = []
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    for name, rx in compiled:
                        if rx.search(line):
                            out.append(new_finding(name, ctype, rel_path, lineno, line))
                    if ctype == "docker-compose":
                        if re.search(r"privileged\s*:\s*true", line):
                            out.append(new_finding("Privileged Container", ctype, rel_path, lineno, line))
                        if re.search(r"0\.0\.0\.0:\d+", line):
                            out.append(new_finding("Exposed on all interfaces", ctype, rel_path, lineno, line))
        except OSError:
            pass
        return out

    with ThreadPoolExecutor(max_workers=8) as ex:
        for result in ex.map(scan_file, targets):
            findings.extend(result)
    return findings


RISK_DESCRIPTIONS = {
    "Run as root": "Containers running as root escalate the blast radius of any container escape",
    "Privileged mode hint": "Privileged containers have full host access, defeating container isolation",
    "Secrets in ENV": "Secrets baked into image ENV are visible in image layers and `docker inspect`",
    "Latest tag": "The :latest tag is mutable; builds are non-reproducible and may pull unexpected code",
    "Secrets in env": "Secrets interpolated in workflow env can leak in logs or to forked PRs",
    "Pull request write": "Write permission on pull-requests lets a compromised job modify the repo",
    "Untrusted input in run": "Interpolating PR-controlled data into run enables script injection in CI",
    "Real secret in example": "A real credential committed in an example file is exposed in git history",
    "Privileged Container": "privileged: true grants the container full host device access",
    "Exposed on all interfaces": "Binding a port to 0.0.0.0 exposes the service to every network interface",
}


if __name__ == "__main__":
    import tempfile
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "Dockerfile"), "w") as f:
        f.write("FROM python:latest\nUSER root\n")
    res = scan_config(d, ["Dockerfile"])
    assert any("Latest tag" in f.title for f in res), res
    print("config_audit.py self-check OK", [f.title for f in res])
