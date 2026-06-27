import os
import re
from itertools import count

from models import Finding, Severity
from scanners.config_audit import _config_type

SEVERITY = {
    "Declared exposed port": Severity.LOW,
    "Published host port": Severity.MEDIUM,
    "Public bind on all interfaces": Severity.HIGH,
    "LoadBalancer service": Severity.MEDIUM,
    "NodePort service": Severity.MEDIUM,
    "Host networking enabled": Severity.HIGH,
    "Container port declared": Severity.INFO,
}

FIXES = {
    "Declared exposed port": "Keep only the ports the service really needs and place them behind a reverse proxy or network policy",
    "Published host port": "Prefer internal-only bindings or localhost during development; publish only what must be public",
    "Public bind on all interfaces": "Bind to 127.0.0.1 or an internal interface unless public access is explicitly required",
    "LoadBalancer service": "Use ClusterIP unless the service must be public, then place it behind controlled ingress and TLS",
    "NodePort service": "Replace with ClusterIP or ingress when external exposure is not required",
    "Host networking enabled": "Avoid hostNetwork unless there is a hard platform requirement and a documented approval",
    "Container port declared": "Verify the port is intentional and covered by auth, TLS, and network policy",
}

DESCRIPTIONS = {
    "Declared exposed port": "The image declares a container port. Confirm the service should be reachable and only through approved paths.",
    "Published host port": "A host port is published in compose. That can expose the service outside the container boundary.",
    "Public bind on all interfaces": "Binding to all interfaces exposes the service to any reachable network interface on the host.",
    "LoadBalancer service": "Kubernetes LoadBalancer services are typically externally reachable; validate this is intended.",
    "NodePort service": "NodePort makes the service accessible on every node; prefer narrower exposure when possible.",
    "Host networking enabled": "hostNetwork lets the pod share the node network namespace and increases exposure.",
    "Container port declared": "Container ports document intent but should still be reviewed for unnecessary exposure.",
}


def scan_exposure(local_path: str, all_files: list[str]) -> list[Finding]:
    targets = [(f, _config_type(f)) for f in all_files]
    targets = [(f, t) for f, t in targets if t in {"Dockerfile", "docker-compose", "kubernetes", "webserver"}]

    findings: list[Finding] = []
    counter = count(1)

    def new_finding(name: str, kind: str, rel_path: str, lineno: int, line: str) -> Finding:
        fid = f"EXP-{next(counter):03d}"
        return Finding(
            id=fid,
            severity=SEVERITY[name],
            category="exposure",
            title=f"{kind}: {name}",
            description=DESCRIPTIONS[name],
            file_path=rel_path,
            line_number=lineno,
            evidence=line.strip()[:200],
            fix_suggestion=FIXES[name],
            auto_fixable=False,
        )

    def scan_file(item) -> list[Finding]:
        rel_path, kind = item
        abs_path = os.path.join(local_path, rel_path)
        out: list[Finding] = []
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    stripped = line.strip()
                    if kind == "Dockerfile":
                        m = re.match(r"^\s*EXPOSE\s+(.+)$", line, flags=re.IGNORECASE)
                        if m:
                            out.append(new_finding("Declared exposed port", kind, rel_path, lineno, line))
                    elif kind == "docker-compose":
                        if re.search(r"(?i)^\s*-\s*['\"]?(?:0\.0\.0\.0:)?\d+:\d+['\"]?\s*$", line):
                            if "0.0.0.0:" in line:
                                out.append(new_finding("Public bind on all interfaces", kind, rel_path, lineno, line))
                            else:
                                out.append(new_finding("Published host port", kind, rel_path, lineno, line))
                    elif kind == "kubernetes":
                        if re.search(r"(?i)^\s*type:\s*LoadBalancer\s*$", line):
                            out.append(new_finding("LoadBalancer service", kind, rel_path, lineno, line))
                        elif re.search(r"(?i)^\s*type:\s*NodePort\s*$", line):
                            out.append(new_finding("NodePort service", kind, rel_path, lineno, line))
                        elif re.search(r"(?i)^\s*hostNetwork:\s*true\s*$", line):
                            out.append(new_finding("Host networking enabled", kind, rel_path, lineno, line))
                        elif re.search(r"(?i)^\s*containerPort:\s*\d+\s*$", line):
                            out.append(new_finding("Container port declared", kind, rel_path, lineno, line))
                    elif kind == "webserver":
                        if re.search(r"(?i)^\s*listen\s+0\.0\.0\.0:\d+", line):
                            out.append(new_finding("Public bind on all interfaces", kind, rel_path, lineno, line))
                        elif re.search(r"(?i)^\s*listen\s+\d+", line) and "ssl" not in stripped.lower():
                            out.append(new_finding("Declared exposed port", kind, rel_path, lineno, line))
        except OSError:
            pass
        return out

    for result in map(scan_file, targets):
        findings.extend(result)
    return findings


if __name__ == "__main__":
    import tempfile

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "docker-compose.yml"), "w", encoding="utf-8") as f:
        f.write("services:\n  app:\n    ports:\n      - '0.0.0.0:8080:80'\n")
    res = scan_exposure(d, ["docker-compose.yml"])
    assert any("Public bind on all interfaces" in f.title for f in res), res
    print("exposure.py self-check OK", [f.title for f in res])
