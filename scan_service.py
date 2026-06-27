import hashlib
import difflib
import json
import os
import re
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import config
from models import Finding, ScanResult, Severity

SCAN_CACHE_DIR = Path(config.CLONE_BASE_DIR) / ".scan_cache"
SCAN_INDEX_PATH = SCAN_CACHE_DIR / "latest_index.json"
SCAN_HISTORY_PATH = SCAN_CACHE_DIR / "history_index.json"
SCAN_RETENTION_SECONDS = 30 * 24 * 60 * 60
CLONE_RETENTION_SECONDS = 7 * 24 * 60 * 60


def _serialize_finding(finding: Finding) -> dict:
    return {
        **finding.__dict__,
        "severity": finding.severity.value,
    }


def _deserialize_finding(data: dict) -> Finding:
    payload = dict(data)
    payload["severity"] = Severity(payload["severity"])
    return Finding(**payload)


def _repo_key(repo_url: str) -> str:
    return hashlib.sha256(repo_url.encode("utf-8")).hexdigest()


def _scan_key(repo_url: str, commit_sha: str) -> str:
    raw = f"{repo_url}:{commit_sha}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _cache_path(scan_key: str) -> Path:
    return SCAN_CACHE_DIR / f"{scan_key}.json"


def _scan_path(scan_id: str) -> Path:
    return SCAN_CACHE_DIR / f"{scan_id}.json"


def _load_index() -> dict:
    if not SCAN_INDEX_PATH.exists():
        return {}
    try:
        return json.loads(SCAN_INDEX_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_history() -> dict:
    if not SCAN_HISTORY_PATH.exists():
        return {}
    try:
        return json.loads(SCAN_HISTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_index(index: dict) -> None:
    SCAN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_INDEX_PATH.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")


def _save_history(history: dict) -> None:
    SCAN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_HISTORY_PATH.write_text(json.dumps(history, indent=2, sort_keys=True), encoding="utf-8")


def _prune_cache_files() -> None:
    if not SCAN_CACHE_DIR.exists():
        return
    now = time.time()
    for path in SCAN_CACHE_DIR.glob("*.json"):
        if path.name in {SCAN_INDEX_PATH.name, SCAN_HISTORY_PATH.name}:
            continue
        try:
            if now - path.stat().st_mtime > SCAN_RETENTION_SECONDS:
                path.unlink(missing_ok=True)
        except OSError:
            continue


def _prune_stale_clones() -> None:
    base = Path(config.CLONE_BASE_DIR)
    if not base.exists():
        return
    now = time.time()
    for entry in base.iterdir():
        if not entry.is_dir() or entry.name == ".scan_cache":
            continue
        match = re.search(r"_(\d+)$", entry.name)
        if not match:
            continue
        try:
            created_at = int(match.group(1))
        except ValueError:
            continue
        if now - created_at > CLONE_RETENTION_SECONDS:
            try:
                import shutil

                shutil.rmtree(entry, ignore_errors=True)
            except Exception:
                pass


def _save_cache(
    scan_id: str,
    repo_url: str,
    commit_sha: str,
    repo_name: str,
    findings: list[Finding],
    scan_errors: list[str],
    scanner_status: dict,
    duration_sec: float,
    started_at: str,
    finished_at: str,
) -> str:
    scan_key = _scan_key(repo_url, commit_sha)
    SCAN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "scan_id": scan_id,
        "repo_url": repo_url,
        "repo_name": repo_name,
        "commit_sha": commit_sha,
        "scan_key": scan_key,
        "saved_at": time.time(),
        "findings": [_serialize_finding(f) for f in findings],
        "scan_errors": scan_errors,
        "scanner_status": scanner_status,
        "duration_sec": duration_sec,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    _scan_path(scan_id).write_text(json.dumps(payload), encoding="utf-8")
    index = _load_index()
    index[_repo_key(repo_url)] = scan_id
    _save_index(index)
    history = _load_history()
    repo_history = history.get(_repo_key(repo_url), [])
    repo_history = [scan_id] + [item for item in repo_history if item != scan_id]
    history[_repo_key(repo_url)] = repo_history[:50]
    _save_history(history)
    _prune_cache_files()
    return scan_key


def _load_cache_by_repo(repo_url: str) -> dict | None:
    index = _load_index()
    scan_id = index.get(_repo_key(repo_url))
    if not scan_id:
        return None
    path = _scan_path(scan_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_cache_by_scan_id(scan_id: str) -> dict | None:
    path = _scan_path(scan_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _repo_commit_sha(local_path: str) -> str:
    result = subprocess.run(
        ["git", "-C", local_path, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _run_scanner(func, *args) -> tuple[list[Finding], list[str]]:
    try:
        return func(*args), []
    except Exception as exc:
        return [], [f"{func.__module__}.{func.__name__}: {exc}"]


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.category, finding.title, finding.file_path, finding.line_number, finding.evidence)
        existing = deduped.get(key)
        if not existing or _severity_rank(finding.severity) > _severity_rank(existing.severity):
            deduped[key] = finding
    return list(deduped.values())


def _unified_diff(path: str, original: str, updated: str) -> str | None:
    if original == updated:
        return None
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=path,
        tofile=path,
        lineterm="",
    )
    patch = "\n".join(diff)
    return patch if patch.strip() else None


def _replace_once(content: str, old: str, new: str) -> str | None:
    if old not in content:
        return None
    return content.replace(old, new, 1)


def _replace_regex_once(content: str, pattern: str, replacement: str) -> str | None:
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.MULTILINE)
    if count == 0 or updated == content:
        return None
    return updated


def _remove_line(content: str, needle: str) -> str | None:
    lines = content.splitlines(keepends=True)
    updated = [line for line in lines if needle not in line]
    if len(updated) == len(lines):
        return None
    return "".join(updated)


def _mask_env_secret(content: str) -> str | None:
    updated, count = re.subn(
        r"(?m)^(\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(['\"]?)[^#\n\r]+(\2)",
        r"\1\g<2>CHANGE_ME\3",
        content,
        count=1,
    )
    if count == 0 or updated == content:
        return None
    return updated


def _attach_fix_patches(local_path: str, findings: list[Finding]) -> None:
    contents: dict[str, str] = {}

    def read_file(rel_path: str) -> str | None:
        if rel_path in contents:
            return contents[rel_path]
        abs_path = os.path.join(local_path, rel_path)
        try:
            text = Path(abs_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        contents[rel_path] = text
        return text

    for finding in findings:
        if finding.fix_patch:
            continue
        if not finding.file_path:
            continue
        original = read_file(finding.file_path)
        if original is None:
            continue
        updated = None
        title = finding.title

        if title in {"Hardcoded Bind All", "Hardcoded Bind All detected", "Exposed on all interfaces", "Exposed on all interfaces detected"}:
            updated = _replace_once(original, "0.0.0.0", "127.0.0.1")
        elif title in {"Shell Injection", "Shell Injection detected"} and finding.file_path.endswith(".py"):
            updated = _replace_regex_once(original, r"shell\s*=\s*True", "shell=False")
        elif title in {"Debug Mode", "Debug Mode detected"}:
            updated = _replace_once(original, "debug=True", "debug=False") or _replace_once(original, "debug = True", "debug = False")
        elif title in {"Privileged Container", "Privileged Container detected", "Privileged mode hint", "Privileged mode hint detected"}:
            updated = _remove_line(original, "privileged: true") or _remove_line(original, "--privileged")
        elif title in {"World Writable", "World Writable detected"}:
            updated = _replace_once(original, "chmod 777", "chmod 755") or _replace_once(original, "chmod a+w", "chmod u+w") or _replace_once(original, "chmod o+w", "chmod u+w")
        elif title in {"Unquoted Variable", "Unquoted Variable detected"}:
            updated = re.subn(r"\[\s+\$([A-Za-z_][A-Za-z0-9_]*)\s+([=!])", r'[ "$\1" \2', original, count=1)[0]
            if updated == original:
                updated = None
        elif title in {"TLS Skip Verify", "TLS Skip Verify detected"}:
            updated = _replace_once(original, "InsecureSkipVerify: true", "InsecureSkipVerify: false")
        elif finding.file_path.endswith((".env.example", ".env.sample")) and any(
            token in title for token in ("Secret", "Key", "Token", "Credential", "Password")
        ):
            updated = _mask_env_secret(original)

        if updated and updated != original:
            patch = _unified_diff(finding.file_path, original, updated)
            if patch:
                finding.fix_patch = patch
                finding.auto_fixable = True


def _severity_rank(severity: Severity) -> int:
    order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    return order.get(severity, 0)


def _emit(progress_cb: Callable[[dict], None] | None, step: int, label: str, status: str = "in_progress") -> None:
    if progress_cb:
        progress_cb(
            {
                "type": "progress",
                "step": step,
                "label": label,
                "status": status,
                "timestamp": _now_iso(),
            }
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_repository(
    repo_url: str,
    github_token: str = "",
    model: str | None = None,
    progress_cb: Callable[[dict], None] | None = None,
) -> dict:
    import agent
    import fetcher
    from scanners import code, config_audit, deps, secrets

    local_path = None
    started_at = time.perf_counter()
    started_iso = _now_iso()
    scan_id = uuid.uuid4().hex
    scan_errors: list[str] = []
    scanner_status: dict[str, dict] = {}
    try:
        _prune_stale_clones()
        _emit(progress_cb, 1, "Fetching repository...")
        local_path, repo_name = fetcher.fetch_repo(repo_url, github_token)
        commit_sha = _repo_commit_sha(local_path)
        all_files = fetcher.list_repo_files(local_path)

        _emit(progress_cb, 2, "Scanning dependencies...")
        _emit(progress_cb, 3, "Detecting secrets...")
        _emit(progress_cb, 4, "Auditing source code...")
        _emit(progress_cb, 5, "Auditing configuration files...")
        with ThreadPoolExecutor(max_workers=4) as pool:
            dep_fut = pool.submit(_run_scanner, deps.scan_dependencies, local_path)
            sec_fut = pool.submit(_run_scanner, secrets.scan_secrets, local_path, all_files)
            code_fut = pool.submit(_run_scanner, code.scan_code, local_path, all_files)
            cfg_fut = pool.submit(_run_scanner, config_audit.scan_config, local_path, all_files)
            dep_res, sec_res, code_res, cfg_res = [f.result() for f in (dep_fut, sec_fut, code_fut, cfg_fut)]

        dep_findings, dep_errors = dep_res
        sec_findings, sec_errors = sec_res
        code_findings, code_errors = code_res
        cfg_findings, cfg_errors = cfg_res
        scan_errors.extend(dep_errors + sec_errors + code_errors + cfg_errors)

        scanner_status["deps"] = {
            "status": "ok" if not dep_errors else "error",
            "findings": len(dep_findings),
            "errors": dep_errors,
        }
        scanner_status["secrets"] = {
            "status": "ok" if not sec_errors else "error",
            "findings": len(sec_findings),
            "errors": sec_errors,
        }
        scanner_status["code"] = {
            "status": "ok" if not code_errors else "error",
            "findings": len(code_findings),
            "errors": code_errors,
        }
        scanner_status["config"] = {
            "status": "ok" if not cfg_errors else "error",
            "findings": len(cfg_findings),
            "errors": cfg_errors,
        }

        try:
            _emit(progress_cb, 6, "Scanning git history...")
            from scanners.git_history import scan_git_history
            git_findings, git_errors = _run_scanner(scan_git_history, local_path)
            scan_errors.extend(git_errors)
        except Exception as exc:
            git_findings = []
            git_errors = [f"scanners.git_history.scan_git_history: {exc}"]
            scan_errors.extend(git_errors)

        scanner_status["git_history"] = {
            "status": "ok" if not git_errors else "error",
            "findings": len(git_findings),
            "errors": git_errors,
        }

        findings = _dedupe_findings(dep_findings + sec_findings + code_findings + cfg_findings + git_findings)
        _attach_fix_patches(local_path, findings)

        result = ScanResult(
            repo_url=repo_url,
            repo_name=repo_name,
            local_path=local_path,
            findings=findings,
            scan_errors=scan_errors,
        )

        _emit(progress_cb, 7, "AI analysis with Regolo...")
        report = agent.analyze(repo_url, result, model or None)
        duration_sec = round(time.perf_counter() - started_at, 3)
        finished_at = _now_iso()
        scan_key = _save_cache(
            scan_id,
            repo_url,
            commit_sha,
            repo_name,
            findings,
            scan_errors,
            scanner_status,
            duration_sec,
            started_iso,
            finished_at,
        )

        return {
            "scan_id": scan_id,
            "report": report,
            "findings": [_serialize_finding(f) for f in findings],
            "stats": {
                "critical": result.critical_count(),
                "high": result.high_count(),
                "medium": len(result.by_severity(Severity.MEDIUM)),
        "low": len(result.by_severity(Severity.LOW)),
        "total_files": len(all_files),
        "git_findings": len(git_findings),
        "scan_errors": len(scan_errors),
        "auto_fixable": len([f for f in findings if f.auto_fixable]),
    },
            "repo_name": repo_name,
            "commit_sha": commit_sha,
            "scan_key": scan_key,
            "started_at": started_iso,
            "finished_at": finished_at,
            "duration_sec": duration_sec,
            "scan_errors": scan_errors,
            "scanner_status": scanner_status,
        }
    finally:
        if local_path:
            try:
                fetcher.cleanup_repo(local_path)
            except Exception:
                pass


def get_cached_findings(repo_url: str) -> list[Finding]:
    cached = _load_cache_by_repo(repo_url)
    if not cached:
        return []
    try:
        return [_deserialize_finding(item) for item in cached.get("findings", [])]
    except Exception:
        return []


def get_cache_metadata(repo_url: str) -> dict | None:
    cached = _load_cache_by_repo(repo_url)
    if not cached:
        return None
    return {
        "repo_name": cached.get("repo_name", ""),
        "commit_sha": cached.get("commit_sha", ""),
        "scan_key": cached.get("scan_key", ""),
        "saved_at": cached.get("saved_at"),
        "scan_errors": cached.get("scan_errors", []),
    }


def list_scan_history(repo_url: str) -> list[dict]:
    history = _load_history()
    repo_history = history.get(_repo_key(repo_url), [])
    out = []
    for scan_id in repo_history:
        cached = _load_cache_by_scan_id(scan_id)
        if not cached:
            continue
        out.append(
            {
                "scan_id": cached.get("scan_id", scan_id),
                "repo_url": cached.get("repo_url", repo_url),
                "repo_name": cached.get("repo_name", ""),
                "commit_sha": cached.get("commit_sha", ""),
                "scan_key": cached.get("scan_key", ""),
                "saved_at": cached.get("saved_at"),
                "duration_sec": cached.get("duration_sec"),
                "findings_count": len(cached.get("findings", [])),
                "scan_errors": cached.get("scan_errors", []),
            }
        )
    return out


def get_scan_record(scan_id: str) -> dict | None:
    return _load_cache_by_scan_id(scan_id)


def delete_scan_record(scan_id: str) -> bool:
    cached = _load_cache_by_scan_id(scan_id)
    if not cached:
        return False
    try:
        _scan_path(scan_id).unlink(missing_ok=True)
    except Exception:
        pass
    history = _load_history()
    repo_key = _repo_key(cached.get("repo_url", ""))
    repo_history = history.get(repo_key, [])
    remaining = [item for item in repo_history if item != scan_id]
    history[repo_key] = remaining
    _save_history(history)
    index = _load_index()
    if index.get(repo_key) == scan_id:
        if remaining:
            index[repo_key] = remaining[0]
        else:
            index.pop(repo_key, None)
        _save_index(index)
    return True
