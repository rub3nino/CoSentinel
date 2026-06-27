import asyncio
import shutil
import unittest
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import agent
import pr_creator
import scan_service
import server
import fetcher
from scanners import code, config_audit, deps, secrets
from models import Finding, Severity


class ServerHttpTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)
        self._patches = []

    def tearDown(self):
        for obj, name, value in reversed(self._patches):
            setattr(obj, name, value)

    def _patch(self, obj, name, value):
        self._patches.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def _sample_finding(self):
        return Finding(
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

    def test_health_and_models(self):
        self._patch(agent, "get_available_models", lambda: ["gpt-4o", "gpt-4o-mini"])

        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")

        models = self.client.get("/api/models")
        self.assertEqual(models.status_code, 200)
        self.assertEqual(models.json()["models"], ["gpt-4o", "gpt-4o-mini"])

    def test_scan_and_create_pr_routes(self):
        finding = self._sample_finding()

        def fake_scan(repo_url, github_token="", model=None, progress_cb=None):
            if progress_cb:
                progress_cb({"type": "progress", "step": 1, "label": "Fetching repository...", "timestamp": "2026-01-01T00:00:00+00:00"})
            return {
                "report": "report",
                "scan_id": "scan-123",
                "findings": [finding.__dict__ | {"severity": finding.severity.value}],
                "stats": {"critical": 1, "high": 0, "medium": 0, "low": 0, "total_files": 1, "git_findings": 0, "scan_errors": 0},
                "repo_name": "demo",
                "commit_sha": "abc",
                "scan_key": "scan-key",
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:01+00:00",
                "duration_sec": 1.0,
                "scan_errors": [],
                "scanner_status": {"deps": {"status": "ok", "findings": 0, "errors": []}},
            }

        self._patch(scan_service, "scan_repository", fake_scan)
        self._patch(scan_service, "get_cached_findings", lambda repo_url: [finding])
        self._patch(pr_creator, "create_fix_pr", lambda repo_url, github_token, finding_ids, all_findings: "https://github.com/example/pr/1")

        scan = self.client.post("/api/scan", json={"repo_url": "https://github.com/example/demo"})
        self.assertEqual(scan.status_code, 200)
        self.assertEqual(scan.json()["repo_name"], "demo")
        self.assertEqual(scan.json()["stats"]["critical"], 1)
        self.assertIn("scan_id", scan.json())
        self.assertIn("scanner_status", scan.json())
        self.assertIn("deps", scan.json()["scanner_status"])

        pr = self.client.post(
            "/api/create-pr",
            json={
                "repo_url": "https://github.com/example/demo",
                "github_token": "token",
                "finding_ids": ["SEC-001"],
            },
        )
        self.assertEqual(pr.status_code, 200)
        self.assertEqual(pr.json()["pr_url"], "https://github.com/example/pr/1")

    def test_scan_stream_emits_events(self):
        def fake_scan(repo_url, github_token="", model=None, progress_cb=None):
            if progress_cb:
                progress_cb({"type": "progress", "step": 1, "label": "Fetching repository...", "timestamp": "2026-01-01T00:00:00+00:00"})
                progress_cb({"type": "progress", "step": 2, "label": "Scanning dependencies...", "timestamp": "2026-01-01T00:00:01+00:00"})
            return {
                "report": "report",
                "findings": [],
                "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_files": 1, "git_findings": 0, "scan_errors": 0},
                "repo_name": "demo",
                "commit_sha": "abc",
                "scan_key": "scan-key",
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:02+00:00",
                "duration_sec": 2.0,
                "scan_errors": [],
            }

        self._patch(scan_service, "scan_repository", fake_scan)

        response = self.client.get("/api/scan/stream", params={"repo_url": "https://github.com/example/demo"})
        self.assertEqual(response.status_code, 200)
        body = response.text
        self.assertIn('"type": "progress"', body)
        self.assertIn('"type": "result"', body)
        self.assertIn('"duration_sec": 2.0', body)

    def test_scan_history_routes(self):
        tmp_repo = tempfile.mkdtemp()
        cache_dir = Path(tempfile.mkdtemp())
        finding = self._sample_finding()
        try:
            self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (tmp_repo, "demo"))
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

            scan = self.client.post("/api/scan", json={"repo_url": "https://github.com/example/demo"})
            self.assertEqual(scan.status_code, 200)
            scan_id = scan.json()["scan_id"]

            history = self.client.get("/api/scans", params={"repo_url": "https://github.com/example/demo"})
            self.assertEqual(history.status_code, 200)
            self.assertEqual(history.json()["scans"][0]["scan_id"], scan_id)

            detail = self.client.get(f"/api/scans/{scan_id}")
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json()["scan_id"], scan_id)

            deleted = self.client.delete(f"/api/scans/{scan_id}")
            self.assertEqual(deleted.status_code, 200)
            self.assertTrue(deleted.json()["deleted"])

            history_after = self.client.get("/api/scans", params={"repo_url": "https://github.com/example/demo"})
            self.assertEqual(history_after.status_code, 200)
            self.assertEqual(history_after.json()["scans"], [])
        finally:
            shutil.rmtree(tmp_repo, ignore_errors=True)
            shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
