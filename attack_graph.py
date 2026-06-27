"""Correlate scanner findings into plausible entry points (attack paths)."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from models import Finding, Severity


@dataclass
class EntryPoint:
    id: str
    severity: str
    status: str  # INFERRED | CONFIRMED
    title: str
    narrative: str
    finding_ids: list[str]
    likelihood: str  # high | medium | low

    def to_dict(self) -> dict:
        return asdict(self)


def _by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {}
    for f in findings:
        out.setdefault(f.category, []).append(f)
    return out


def _ids(*groups: list[Finding]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        for f in group:
            if f.id not in seen:
                seen.add(f.id)
                out.append(f.id)
    return out


def _sev_max(*groups: list[Finding]) -> Severity:
    order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
    best = Severity.INFO
    for group in groups:
        for f in group:
            if order.get(f.severity, 0) > order.get(best, 0):
                best = f.severity
    return best


def _has_public_exposure(exposure: list[Finding]) -> list[Finding]:
    keys = ("Public bind", "Published host port", "LoadBalancer", "NodePort", "Host networking")
    return [f for f in exposure if any(k in f.title for k in keys)]


def _has_debug(code: list[Finding]) -> list[Finding]:
    return [f for f in code if "Debug Mode" in f.title]


def _critical_secrets(secrets: list[Finding]) -> list[Finding]:
    return [f for f in secrets if f.severity in {Severity.CRITICAL, Severity.HIGH}]


def _git_secrets(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.id.startswith("GIT-") or "git history" in f.title.lower()]


def _sensitive_routes(routes: list[Finding]) -> list[Finding]:
    return routes


def _critical_deps(deps: list[Finding]) -> list[Finding]:
    return [f for f in deps if f.severity in {Severity.CRITICAL, Severity.HIGH}]


def _network_confirms(ep_title: str, network: list[Finding]) -> bool:
    if not network:
        return False
    title = ep_title.lower()
    for f in network:
        nt = f.title.lower()
        if "sensitive path" in nt or "discovered path" in nt:
            if any(token in nt for token in ("admin", "debug", "actuator", "graphql", "config")):
                return True
        if "redis exposed" in nt or "mongodb exposed" in nt:
            return "redis" in title or "database" in title
        if "missing hsts" in nt or "missing content-security" in nt:
            if "debug" in title or "admin" in title:
                return True
        if "http alt port" in nt or "telnet" in nt or "ftp open" in nt:
            if "exposed" in title or "public" in title:
                return True
    return False


def _deploy_targets(targets: list[Finding]) -> list[Finding]:
    return targets


def _weak_auth(auth: list[Finding]) -> list[Finding]:
    return [f for f in auth if f.severity in {Severity.CRITICAL, Severity.HIGH}]


def build_entry_points(findings: list[Finding], live_target: str | None = None) -> list[dict]:
    grouped = _by_category(findings)
    exposure = grouped.get("exposure", [])
    code = grouped.get("code", [])
    secrets = grouped.get("secret", [])
    git = grouped.get("git_history", []) or [f for f in findings if f.category == "git_history"]
    routes = grouped.get("route", [])
    deps = grouped.get("dependency", [])
    network = grouped.get("network", [])
    targets = grouped.get("target", [])
    auth = grouped.get("auth", [])

    public = _has_public_exposure(exposure)
    debug = _has_debug(code)
    crit_secrets = _critical_secrets(secrets)
    git_sec = _git_secrets(findings)
    sens_routes = _sensitive_routes(routes)
    crit_deps = _critical_deps(deps)
    deploy_targets = _deploy_targets(targets)
    weak_auth = _weak_auth(auth)

    candidates: list[EntryPoint] = []
    counter = 0

    def add(severity: Severity, title: str, narrative: str, ids: list[str], likelihood: str) -> None:
        nonlocal counter
        if not ids:
            return
        counter += 1
        status = "CONFIRMED" if live_target and network and _network_confirms(title, network) else "INFERRED"
        candidates.append(
            EntryPoint(
                id=f"EP-{counter:03d}",
                severity=severity.value,
                status=status,
                title=title,
                narrative=narrative,
                finding_ids=ids,
                likelihood=likelihood,
            )
        )

    if public and debug:
        add(
            Severity.CRITICAL,
            "Public debug surface",
            "Service binds publicly and debug mode is enabled — stack traces and potentially RCE reachable from the network.",
            _ids(public[:1], debug[:1]),
            "high",
        )

    if public and sens_routes:
        add(
            Severity.CRITICAL,
            "Sensitive route on exposed service",
            "A sensitive HTTP route is declared while the service is configured for external exposure.",
            _ids(public[:1], sens_routes[:2]),
            "high",
        )

    if crit_secrets and public:
        add(
            Severity.CRITICAL,
            "Leaked credentials on exposed deployment",
            "High-value secret in repo plus network exposure — credentials may be usable against a reachable service.",
            _ids(crit_secrets[:1], public[:1]),
            "high",
        )

    if crit_secrets and deploy_targets:
        url = deploy_targets[0].title.split(": ", 1)[-1]
        add(
            Severity.CRITICAL,
            f"Leaked credentials for declared target {url}",
            "Secret in repository references a deployment URL documented in the repo — attacker may know where to use stolen credentials.",
            _ids(crit_secrets[:1], deploy_targets[:1]),
            "high",
        )

    if weak_auth and (public or sens_routes):
        add(
            Severity.CRITICAL,
            "Weak auth on exposed surface",
            "Authentication weakness (JWT/CORS/session) combined with external exposure or sensitive routes.",
            _ids(weak_auth[:1], (public or sens_routes)[:1]),
            "high",
        )

    if git_sec and sens_routes:
        add(
            Severity.HIGH,
            "Historical secret plus live admin route",
            "Secret persisted in git history while a sensitive route remains — rotation alone may not close access.",
            _ids(git_sec[:1], sens_routes[:1]),
            "medium",
        )

    if crit_deps and (sens_routes or public):
        add(
            Severity.HIGH,
            "Critical CVE on reachable surface",
            "Critical dependency issue combined with external exposure or sensitive route — higher chance of remote abuse.",
            _ids(crit_deps[:1], (sens_routes or public)[:1]),
            "medium",
        )

    for route in sens_routes[:3]:
        add(
            Severity.HIGH,
            f"Unauthenticated entry: {route.title.split(': ', 1)[-1]}",
            route.description,
            [route.id],
            "medium",
        )

    if live_target and network:
        risky = [f for f in network if f.severity in {Severity.CRITICAL, Severity.HIGH}]
        if risky:
            add(
                _sev_max(risky),
                f"Confirmed external exposure on {live_target}",
                "Live validation found high-severity external issues on the authorized target.",
                _ids(risky[:3]),
                "high",
            )

    # dedupe by finding_ids set
    seen: set[tuple[str, ...]] = set()
    unique: list[dict] = []
    for ep in candidates:
        key = tuple(sorted(ep.finding_ids))
        if key in seen:
            continue
        seen.add(key)
        unique.append(ep.to_dict())

    unique.sort(key=lambda e: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(e["severity"], 9))
    return unique


if __name__ == "__main__":
    from models import Finding

    sample = [
        Finding("EXP-001", Severity.HIGH, "exposure", "docker-compose: Public bind on all interfaces", "", "docker-compose.yml", 4, "0.0.0.0:8080", fix_suggestion="bind localhost"),
        Finding("CODE-001", Severity.MEDIUM, "code", "Debug Mode", "", "app.py", 1, "debug=True", fix_suggestion="disable"),
    ]
    eps = build_entry_points(sample)
    assert eps and eps[0]["status"] == "INFERRED", eps
    print("attack_graph.py self-check OK", eps[0]["title"])
