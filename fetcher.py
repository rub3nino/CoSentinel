import os
import shutil
import subprocess
import time
from pathlib import Path

import config


def _normalize_repo_url(repo_url: str, github_token: str = "") -> str:
    url = repo_url.strip()
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:") :]
    if url.startswith("https://github.com/"):
        path = url[len("https://github.com/") :].strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not path or "/" not in path:
            raise ValueError("Invalid GitHub URL")
        if github_token:
            return f"https://{github_token}@github.com/{path}"
        return f"https://github.com/{path}"
    raise ValueError("Invalid GitHub URL")


def _repo_name_from_url(repo_url: str) -> str:
    path = repo_url.rstrip("/").split("github.com/", 1)[-1]
    if path.endswith(".git"):
        path = path[:-4]
    if "/" not in path:
        raise ValueError("Invalid GitHub URL")
    return path.rsplit("/", 1)[-1]


def fetch_repo(repo_url: str, github_token: str = "") -> tuple[str, str]:
    clone_url = _normalize_repo_url(repo_url, github_token)
    repo_name = _repo_name_from_url(repo_url)
    dest = Path(config.CLONE_BASE_DIR) / f"{repo_name}_{int(time.time())}"
    dest.parent.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(dest), "pull"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "git pull failed")
        return str(dest), repo_name

    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    result = subprocess.run(
        ["git", "clone", clone_url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git clone failed")
    return str(dest), repo_name


def list_repo_files(local_path: str) -> list[str]:
    root = Path(local_path)
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target"}
    files: list[str] = []

    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        current = Path(current_root)
        for filename in filenames:
            path = current / filename
            if path.suffix in config.SKIP_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > config.MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            files.append(str(path.relative_to(root)).replace(os.sep, "/"))
    return files


def cleanup_repo(local_path: str) -> None:
    shutil.rmtree(local_path, ignore_errors=True)


if __name__ == "__main__":
    print("fetcher OK")
