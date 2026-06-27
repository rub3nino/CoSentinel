import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from models import Finding, Severity

URL_INLINE = re.compile(r"https?://[^\s'\"<>)\]\`,]+")
ENV_URL = re.compile(
    r"(?i)(?:BASE_URL|APP_URL|API_URL|SITE_URL|DOMAIN|HOST|"
    r"VITE_[A-Z0-9_]*URL|NEXT_PUBLIC_[A-Z0-9_]*URL|"
    r"REACT_APP_[A-Z0-9_]*URL|PUBLIC_URL|CANONICAL_URL)"
    r"\s*[=:]\s*['\"]([^'\"]+)['\"]"
)
CNAME = re.compile(r"(?i)cname\s*[=:]\s*['\"]?([a-z0-9.-]+\.[a-z]{2,})")

SKIP_HOSTS = {
    "github.com", "github.io", "gitlab.com", "bitbucket.org",
    "npmjs.org", "pypi.org", "registry.npmjs.org",
    "example.com", "example.org", "localhost", "127.0.0.1",
    "w3.org", "schema.org", "fonts.googleapis.com", "fonts.gstatic.com",
    "cdn.jsdelivr.net", "unpkg.com", "img.shields.io",
}
SKIP_SUFFIX = (".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".md")

INTERESTING_FILES = {
    "readme.md", "deploy.md", "deployment.md", "docker-compose.yml", "docker-compose.yaml",
    "vercel.json", "railway.toml", "fly.toml", "wrangler.toml", "netlify.toml",
    "render.yaml", "app.yaml", "Procfile",
}


def _configish(rel_path: str) -> bool:
    base = os.path.basename(rel_path).lower()
    p = rel_path.replace("\\", "/").lower()
    if base in INTERESTING_FILES:
        return True
    if ".github/workflows/" in p and base.endswith((".yml", ".yaml")):
        return True
    if base.endswith((".env.example", ".env.sample", ".env.test")):
        return True
    return False


def _normalize_url(raw: str) -> str | None:
    raw = raw.strip().rstrip(".,;)")
    if not raw.startswith(("http://", "https://")):
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/|$)", raw, re.I):
            raw = f"https://{raw.split('/')[0]}"
        else:
            return None
    try:
        parsed = urlparse(raw)
    except Exception:
        return None
    host = (parsed.hostname or "").lower()
    if not host or host in SKIP_HOSTS or host.endswith(SKIP_SUFFIX):
        return None
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return None
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path if parsed.path and parsed.path != "/" else ""
    return f"{parsed.scheme}://{host}{port}{path}"


def _extract_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for match in URL_INLINE.findall(text):
        url = _normalize_url(match)
        if url:
            found.add(url)
    for match in ENV_URL.findall(text):
        url = _normalize_url(match)
        if url:
            found.add(url)
    for match in CNAME.findall(text):
        url = _normalize_url(match)
        if url:
            found.add(url)
    return found


def _scan_file(local_path: str, rel_path: str) -> list[tuple[str, str, int]]:
    abs_path = os.path.join(local_path, rel_path)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError:
        return []
    urls = _extract_from_text(text)
    if not urls:
        return []
    # first line containing each url for evidence
    hits: list[tuple[str, str, int]] = []
    lines = text.splitlines()
    for url in sorted(urls):
        host = urlparse(url).hostname or url
        for idx, line in enumerate(lines, 1):
            if host in line or url in line:
                hits.append((url, line.strip()[:200], idx))
                break
        else:
            hits.append((url, url, 1))
    return hits


def scan_targets(local_path: str, all_files: list[str]) -> list[Finding]:
    files = [f for f in all_files if _configish(f) or f.lower().endswith((".md", ".yml", ".yaml", ".toml", ".json", ".env.example", ".env.sample"))]
    seen: set[str] = set()
    findings: list[Finding] = []
    counter = 0

    def scan_one(rel_path: str) -> list[tuple[str, str, int]]:
        return _scan_file(local_path, rel_path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for rel_path, hits in zip(files, pool.map(scan_one, files)):
            for url, evidence, lineno in hits:
                if url in seen:
                    continue
                seen.add(url)
                counter += 1
                findings.append(
                    Finding(
                        id=f"TGT-{counter:03d}",
                        severity=Severity.INFO,
                        category="target",
                        title=f"Deploy target declared: {url}",
                        description="URL or domain referenced in repo config/docs — candidate for authorized live validation.",
                        file_path=rel_path,
                        line_number=lineno,
                        evidence=evidence,
                        fix_suggestion="Ensure this endpoint is intended to be public and is covered by your live validation scope.",
                        auto_fixable=False,
                    )
                )
    return findings


def list_target_urls(findings: list[Finding]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for f in findings:
        if f.category != "target":
            continue
        raw = f.title.split(": ", 1)[-1].strip()
        if raw and raw not in seen:
            seen.add(raw)
            urls.append(raw)
    return urls


if __name__ == "__main__":
    import tempfile

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("Production: https://staging.example.com/api\n")
    res = scan_targets(d, ["README.md"])
    assert res and "staging.example.com" in res[0].title, res
    print("targets.py self-check OK", res[0].title)
