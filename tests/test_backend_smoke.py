import asyncio
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest

import agent
import config
import fetcher
import scan_service
import server
import pr_creator
from models import Finding, Severity
from scanners import code, config_audit, deps, secrets


class BackendSmokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.tmp, check=True, capture_output=True)
        with open(os.path.join(self.tmp, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("print('hello')\n")
        subprocess.run(["git", "add", "a.py"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=self.tmp, check=True, capture_output=True)
        self.repo_url = "https://github.com/example/demo-smoke"
        self._patches = []

    def tearDown(self):
        for obj, name, value in reversed(self._patches):
            setattr(obj, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _patch(self, obj, name, value):
        self._patches.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def test_scan_cache_roundtrip_and_health(self):
        findings = [
            Finding(
                id="SEC-001",
                severity=Severity.CRITICAL,
                category="secret",
                title="OpenAI Key detected",
                description="hardcoded",
                file_path="a.py",
                line_number=1,
                evidence="sk-ant***REDACTED***",
                fix_suggestion="rotate",
                auto_fixable=False,
            )
        ]

        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: findings)
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")
        self._patch(pr_creator, "create_fix_pr", lambda repo_url, github_token, finding_ids, all_findings: f"pr://{len(finding_ids)}:{len(all_findings)}")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(result["repo_name"], "demo-smoke")
        self.assertEqual(result["stats"]["critical"], 1)
        cached = scan_service.get_cached_findings(self.repo_url)
        self.assertEqual(len(cached), 1)
        self.assertEqual(cached[0].id, "SEC-001")

        pr = asyncio.run(
            server.create_pr(
                server.PRRequest(repo_url=self.repo_url, github_token="token", finding_ids=["SEC-001"])
            )
        )
        self.assertEqual(pr["pr_url"], "pr://1:1")

        health = asyncio.run(server.health())
        self.assertEqual(health["status"], "ok")
        self.assertIn("git_history", health["scanners"])

    def test_progress_events_are_emitted(self):
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        events = []

        result = scan_service.scan_repository(self.repo_url, "", None, lambda event: events.append(event))
        self.assertEqual(result["repo_name"], "demo-smoke")
        labels = [event["label"] for event in events if event.get("type") == "progress"]
        self.assertEqual(
            labels,
            [
                "Fetching repository...",
                "Scanning dependencies...",
                "Detecting secrets...",
                "Auditing source code...",
                "Auditing configuration files...",
                "Scanning git history...",
                "AI analysis with Regolo...",
            ],
        )

        self.assertTrue(all("timestamp" in event for event in events if event.get("type") == "progress"))
        self.assertIn("started_at", result)
        self.assertIn("finished_at", result)
        self.assertGreaterEqual(result["duration_sec"], 0)

    def test_partial_scanner_error_is_captured(self):
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: (_ for _ in ()).throw(RuntimeError("deps boom")))
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(result["stats"]["scan_errors"], 1)
        self.assertEqual(len(result["scan_errors"]), 1)
        self.assertIn("deps boom", result["scan_errors"][0])
        self.assertEqual(result["repo_name"], "demo-smoke")
        self.assertEqual(result["scanner_status"]["deps"]["status"], "error")
        self.assertEqual(result["scanner_status"]["secrets"]["status"], "ok")

    def test_pr_creator_rejects_empty_patch_set(self):
        self._patch(pr_creator, "_can_fix", lambda finding: True)
        self._patch(pr_creator, "_gh", lambda url, headers: {"default_branch": "main"} if url.endswith("repos/example/demo-smoke") else {"object": {"sha": "abc"}})
        self._patch(pr_creator, "_gh_post", lambda url, headers, body: {"html_url": "https://example.com/pr"})
        self._patch(pr_creator, "_gh_patch", lambda url, headers, body: {})
        self._patch(pr_creator, "_apply_patch_commit", lambda base_url, headers, branch, finding: False)

        finding = Finding(
            id="CODE-001",
            severity=Severity.HIGH,
            category="code",
            title="Debug Mode",
            description="debug",
            file_path="a.py",
            line_number=1,
            evidence="debug=True",
            fix_suggestion="disable debug",
            auto_fixable=False,
        )

        with self.assertRaises(RuntimeError):
            pr_creator.create_fix_pr(self.repo_url, "token", ["CODE-001"], [finding])

    def test_cleanup_prunes_stale_cache_and_clones(self):
        cache_dir = Path(tempfile.mkdtemp())
        clone_dir = Path(tempfile.mkdtemp())
        old_cache = cache_dir / "old.json"
        old_cache.write_text("{}", encoding="utf-8")
        old_mtime = scan_service.time.time() - (scan_service.SCAN_RETENTION_SECONDS + 10)
        os.utime(old_cache, (old_mtime, old_mtime))

        old_clone = clone_dir / f"demo_{int(scan_service.time.time()) - (scan_service.CLONE_RETENTION_SECONDS + 10)}"
        old_clone.mkdir()

        self._patch(scan_service, "SCAN_CACHE_DIR", cache_dir)
        self._patch(scan_service, "SCAN_INDEX_PATH", cache_dir / "latest_index.json")
        self._patch(config, "CLONE_BASE_DIR", str(clone_dir))

        scan_service._prune_cache_files()
        scan_service._prune_stale_clones()

        self.assertFalse(old_cache.exists())
        self.assertFalse(old_clone.exists())
        shutil.rmtree(cache_dir, ignore_errors=True)
        shutil.rmtree(clone_dir, ignore_errors=True)

    def test_dedup_keeps_single_finding(self):
        duplicate = Finding(
            id="SEC-001",
            severity=Severity.HIGH,
            category="secret",
            title="Duplicate",
            description="dup",
            file_path="a.py",
            line_number=1,
            evidence="same",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [duplicate, duplicate])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["stats"]["critical"], 0)

    def test_history_promotes_previous_scan_after_delete(self):
        cache_dir = Path(tempfile.mkdtemp())
        finding = Finding(
            id="SEC-001",
            severity=Severity.CRITICAL,
            category="secret",
            title="OpenAI Key detected",
            description="hardcoded",
            file_path="a.py",
            line_number=1,
            evidence="sk-ant***REDACTED***",
            fix_suggestion="rotate",
            auto_fixable=False,
        )
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [finding])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")
        self._patch(scan_service, "SCAN_CACHE_DIR", cache_dir)
        self._patch(scan_service, "SCAN_INDEX_PATH", cache_dir / "latest_index.json")
        self._patch(scan_service, "SCAN_HISTORY_PATH", cache_dir / "history_index.json")

        first = scan_service.scan_repository(self.repo_url, "", None)
        second = scan_service.scan_repository(self.repo_url, "", None)
        self.assertNotEqual(first["scan_id"], second["scan_id"])
        history = scan_service.list_scan_history(self.repo_url)
        self.assertEqual(len(history), 2)

        scan_service.delete_scan_record(second["scan_id"])
        history_after = scan_service.list_scan_history(self.repo_url)
        self.assertEqual(len(history_after), 1)
        cached = scan_service.get_cached_findings(self.repo_url)
        self.assertEqual(len(cached), 1)
        shutil.rmtree(cache_dir, ignore_errors=True)

    def test_fix_patch_is_attached_for_simple_debug_mode(self):
        finding = Finding(
            id="CODE-001",
            severity=Severity.MEDIUM,
            category="code",
            title="Debug Mode",
            description="debug",
            file_path="app.py",
            line_number=1,
            evidence="debug=True",
            fix_suggestion="disable debug",
            auto_fixable=False,
        )
        with open(os.path.join(self.tmp, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("debug=True\n")
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["app.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [finding])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["auto_fixable"])
        self.assertIn("--- app.py", result["findings"][0]["fix_patch"])
        self.assertIn("debug=False", result["findings"][0]["fix_patch"])

    def test_fix_patch_is_attached_for_python_shell_injection(self):
        finding = Finding(
            id="CODE-002",
            severity=Severity.CRITICAL,
            category="code",
            title="Shell Injection",
            description="shell",
            file_path="runner.py",
            line_number=1,
            evidence="shell=True",
            fix_suggestion="remove shell=True",
            auto_fixable=False,
        )
        with open(os.path.join(self.tmp, "runner.py"), "w", encoding="utf-8") as fh:
            fh.write("subprocess.run(cmd, shell=True)\n")
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["runner.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [finding])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertTrue(result["findings"][0]["auto_fixable"])
        self.assertIn("shell=False", result["findings"][0]["fix_patch"])

    def test_fix_patch_is_attached_for_env_sample_secret(self):
        finding = Finding(
            id="SEC-777",
            severity=Severity.HIGH,
            category="secret",
            title="Generic Secret detected",
            description="secret",
            file_path=".env.example",
            line_number=1,
            evidence="PASSWORD=supersecret",
            fix_suggestion="replace with placeholder",
            auto_fixable=False,
        )
        with open(os.path.join(self.tmp, ".env.example"), "w", encoding="utf-8") as fh:
            fh.write("PASSWORD=supersecret\n")
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: [".env.example"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [finding])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertTrue(result["findings"][0]["auto_fixable"])
        self.assertIn("CHANGE_ME", result["findings"][0]["fix_patch"])


if __name__ == "__main__":
    unittest.main()
