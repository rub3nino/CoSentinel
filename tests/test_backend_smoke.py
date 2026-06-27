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
from scanners import auth, code, config_audit, crtsh, deps, exposure, github_actions, routes, secrets, semgrep, targets, trivy, wayback

_REAL_SCAN_ROUTES = routes.scan_routes
_REAL_SCAN_TARGETS = targets.scan_targets
_REAL_SCAN_AUTH = auth.scan_auth
_REAL_SCAN_TRIVY = trivy.scan_dockerfiles
_REAL_SCAN_CRTSH = crtsh.scan_crtsh
_REAL_SCAN_GHA = github_actions.scan_github_actions
_REAL_SCAN_WAYBACK = wayback.scan_wayback


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
        self._patch(routes, "scan_routes", lambda local_path, all_files: [])
        self._patch(targets, "scan_targets", lambda local_path, all_files: [])
        self._patch(auth, "scan_auth", lambda local_path, all_files: [])
        self._patch(trivy, "scan_dockerfiles", lambda local_path, all_files: [])
        self._patch(crtsh, "scan_crtsh", lambda domains: [])
        self._patch(github_actions, "scan_github_actions", lambda local_path, all_files: [])
        self._patch(semgrep, "scan_semgrep", lambda local_path: [])
        self._patch(wayback, "scan_wayback", lambda domains: [])

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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")
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
        self.assertIn("exposure", health["scanners"])
        self.assertIn("git_history", health["scanners"])
        self.assertIn("routes", health["scanners"])
        self.assertIn("targets", health["scanners"])
        self.assertIn("auth", health["scanners"])
        self.assertIn("trivy", health["scanners"])
        self.assertIn("crtsh", health["scanners"])
        self.assertIn("github_actions", health["scanners"])
        self.assertIn("wayback", health["scanners"])
        self.assertFalse(health["live_scan_enabled"])
        self.assertIn("demo_repo_url", health)

    def test_progress_events_are_emitted(self):
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

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
                "Auditing source code and routes...",
                "Checking authorized exposure...",
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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(result["stats"]["scan_errors"], 1)
        self.assertEqual(len(result["scan_errors"]), 1)
        self.assertIn("deps boom", result["scan_errors"][0])
        self.assertEqual(result["repo_name"], "demo-smoke")
        self.assertEqual(result["scanner_status"]["deps"]["status"], "error")
        self.assertEqual(result["scanner_status"]["secrets"]["status"], "ok")

    def test_pr_creator_rejects_empty_patch_set(self):
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
        # Set mtime to a value older than CLONE_RETENTION_SECONDS
        old_clone_mtime = scan_service.time.time() - (scan_service.CLONE_RETENTION_SECONDS + 10)
        os.utime(old_clone, (old_clone_mtime, old_clone_mtime))

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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")
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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(len(result["findings"]), 1)
        self.assertTrue(result["findings"][0]["auto_fixable"])
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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

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
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertTrue(result["findings"][0]["auto_fixable"])
        self.assertIn("CHANGE_ME", result["findings"][0]["fix_patch"])

    def test_exposure_scan_detects_public_bindings(self):
        compose = os.path.join(self.tmp, "docker-compose.yml")
        with open(compose, "w", encoding="utf-8") as fh:
            fh.write(
                "services:\n"
                "  app:\n"
                "    ports:\n"
                "      - '0.0.0.0:8080:80'\n"
            )

        findings = exposure.scan_exposure(self.tmp, ["docker-compose.yml"])
        self.assertTrue(any("Public bind on all interfaces" in f.title for f in findings))

    def test_report_includes_exposure_section(self):
        finding = Finding(
            id="EXP-001",
            severity=Severity.MEDIUM,
            category="exposure",
            title="docker-compose: Published host port",
            description="exposure",
            file_path="docker-compose.yml",
            line_number=4,
            evidence="- '8080:80'",
            fix_suggestion="publish only what must be public",
            auto_fixable=False,
        )
        with open(os.path.join(self.tmp, "docker-compose.yml"), "w", encoding="utf-8") as fh:
            fh.write("services:\n  app:\n    ports:\n      - '8080:80'\n")
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["docker-compose.yml"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [finding])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertIn("## Exposure Findings", result["report"])
        self.assertIn("[EXP-001] docker-compose: Published host port", result["report"])


    def test_live_target_triggers_network_scan(self):
        net_finding = Finding(
            id="NET-001",
            severity=Severity.MEDIUM,
            category="network",
            title="Missing HSTS header",
            description="HSTS not set",
            file_path=None,
            line_number=None,
            evidence="Header absent",
            fix_suggestion="Add HSTS",
            auto_fixable=False,
        )

        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")

        import scanners.network as network_mod
        self._patch(network_mod, "scan_network", lambda target: [net_finding])
        self._patch(config, "ENABLE_LIVE_SCAN", True)

        events = []
        result = scan_service.scan_repository(
            self.repo_url, "", None, lambda event: events.append(event), "scanme.nmap.org"
        )
        self.assertEqual(result["live_target"], "scanme.nmap.org")
        self.assertEqual(result["scanner_status"]["network"]["findings"], 1)
        self.assertTrue(any(f["category"] == "network" for f in result["findings"]))
        labels = [e["label"] for e in events if e.get("type") == "progress"]
        self.assertIn("Validating entry points on scanme.nmap.org...", labels)
        self.assertEqual(labels[-1], "AI analysis with Regolo...")


    def test_attack_graph_links_debug_and_exposure(self):
        exp = Finding(
            id="EXP-001",
            severity=Severity.HIGH,
            category="exposure",
            title="docker-compose: Public bind on all interfaces",
            description="exposure",
            file_path="docker-compose.yml",
            line_number=4,
            evidence="0.0.0.0:8080",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        dbg = Finding(
            id="CODE-001",
            severity=Severity.MEDIUM,
            category="code",
            title="Debug Mode",
            description="debug",
            file_path="app.py",
            line_number=1,
            evidence="debug=True",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        import attack_graph

        eps = attack_graph.build_entry_points([exp, dbg])
        self.assertTrue(any(ep["title"] == "Public debug surface" for ep in eps))
        self.assertEqual(eps[0]["status"], "INFERRED")

    def test_routes_scanner_flags_admin_without_auth(self):
        with open(os.path.join(self.tmp, "views.py"), "w", encoding="utf-8") as fh:
            fh.write("@app.route('/admin/dashboard')\ndef admin():\n    return 'ok'\n")
        found = _REAL_SCAN_ROUTES(self.tmp, ["views.py"])
        self.assertEqual(len(found), 1)
        self.assertIn("admin", found[0].title)

    def test_scan_returns_entry_points(self):
        exp = Finding(
            id="EXP-001",
            severity=Severity.HIGH,
            category="exposure",
            title="docker-compose: Public bind on all interfaces",
            description="exposure",
            file_path="docker-compose.yml",
            line_number=4,
            evidence="0.0.0.0:8080",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        dbg = Finding(
            id="CODE-001",
            severity=Severity.MEDIUM,
            category="code",
            title="Debug Mode",
            description="debug",
            file_path="app.py",
            line_number=1,
            evidence="debug=True",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["app.py", "docker-compose.yml"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [dbg])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [exp])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertIn("entry_points", result)
        self.assertTrue(any(ep["title"] == "Public debug surface" for ep in result["entry_points"]))


    def test_targets_and_auth_scanners(self):
        with open(os.path.join(self.tmp, "README.md"), "w", encoding="utf-8") as fh:
            fh.write("Live at https://staging.example.com\n")
        with open(os.path.join(self.tmp, "auth.py"), "w", encoding="utf-8") as fh:
            fh.write("jwt.decode(token, verify=False)\n")
        tg = _REAL_SCAN_TARGETS(self.tmp, ["README.md"])
        au = _REAL_SCAN_AUTH(self.tmp, ["auth.py"])
        self.assertTrue(any("staging.example.com" in f.title for f in tg))
        self.assertTrue(any(f.title == "JWT verify disabled" for f in au))

    def test_attack_graph_secret_plus_target(self):
        sec = Finding(
            id="SEC-001", severity=Severity.CRITICAL, category="secret", title="OpenAI Key detected",
            description="secret", file_path=".env", line_number=1, evidence="sk-***", fix_suggestion="rotate", auto_fixable=False,
        )
        tgt = Finding(
            id="TGT-001", severity=Severity.INFO, category="target", title="Deploy target declared: https://api.example.com",
            description="target", file_path="README.md", line_number=1, evidence="https://api.example.com", fix_suggestion="scope", auto_fixable=False,
        )
        import attack_graph
        eps = attack_graph.build_entry_points([sec, tgt])
        self.assertTrue(any("declared target" in ep["title"] for ep in eps))

    def test_scan_returns_suggested_targets(self):
        tgt = Finding(
            id="TGT-001", severity=Severity.INFO, category="target", title="Deploy target declared: https://api.example.com",
            description="target", file_path="README.md", line_number=1, evidence="https://api.example.com", fix_suggestion="scope", auto_fixable=False,
        )
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["README.md"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(targets, "scan_targets", lambda local_path, all_files: [tgt])

        result = scan_service.scan_repository(self.repo_url, "", None)
        self.assertEqual(result["suggested_targets"], ["https://api.example.com"])

    def test_trivy_flags_unpinned_base(self):
        with open(os.path.join(self.tmp, "Dockerfile"), "w", encoding="utf-8") as fh:
            fh.write("FROM node:latest\nRUN echo hi\n")
        found = _REAL_SCAN_TRIVY(self.tmp, ["Dockerfile"])
        self.assertTrue(any("latest" in f.title.lower() for f in found))

    def test_crtsh_finds_sensitive_subdomains(self):
        tgt = Finding(
            id="TGT-001",
            severity=Severity.INFO,
            category="target",
            title="Deploy target declared: https://api.example.com",
            description="target",
            file_path="README.md",
            line_number=1,
            evidence="https://api.example.com",
            fix_suggestion="scope",
            auto_fixable=False,
        )
        domains = crtsh.collect_domains([tgt], self.repo_url, "")
        self.assertEqual(domains, ["example.com"])

        class FakeResp:
            status_code = 200

            @staticmethod
            def json():
                return [{"name_value": "admin.example.com\napi.example.com"}]

        self._patch(crtsh.requests, "get", lambda url, timeout=20: FakeResp())
        found = _REAL_SCAN_CRTSH(["example.com"])
        self.assertEqual(len(found), 1)
        self.assertIn("admin.example.com", found[0].evidence)

    def test_github_actions_flags_pull_request_target(self):
        wf_dir = os.path.join(self.tmp, ".github", "workflows")
        os.makedirs(wf_dir, exist_ok=True)
        with open(os.path.join(wf_dir, "ci.yml"), "w", encoding="utf-8") as fh:
            fh.write("on:\n  pull_request_target:\n    types: [opened]\n")
        found = _REAL_SCAN_GHA(self.tmp, [".github/workflows/ci.yml"])
        self.assertTrue(any("pull_request_target" in f.title for f in found))

    def test_attack_graph_links_container_and_exposure(self):
        exp = Finding(
            id="EXP-001",
            severity=Severity.HIGH,
            category="exposure",
            title="docker-compose: Public bind on all interfaces",
            description="exposure",
            file_path="docker-compose.yml",
            line_number=4,
            evidence="0.0.0.0:8080",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        ctr = Finding(
            id="TRV-001",
            severity=Severity.MEDIUM,
            category="container",
            title="Unpinned or latest base image: python:latest",
            description="container",
            file_path="Dockerfile",
            line_number=1,
            evidence="FROM python:latest",
            fix_suggestion="pin",
            auto_fixable=False,
        )
        import attack_graph

        eps = attack_graph.build_entry_points([exp, ctr])
        self.assertTrue(any("Container risk" in ep["title"] for ep in eps))

    def test_attack_graph_links_crtsh_and_auth(self):
        crt = Finding(
            id="CRT-001",
            severity=Severity.HIGH,
            category="crtsh",
            title="Sensitive subdomains in CT logs for example.com",
            description="crt",
            file_path=None,
            line_number=None,
            evidence="admin.example.com, staging.example.com",
            fix_suggestion="review",
            auto_fixable=False,
        )
        auth_f = Finding(
            id="AUTH-001",
            severity=Severity.HIGH,
            category="auth",
            title="JWT verify disabled",
            description="auth",
            file_path="app.py",
            line_number=1,
            evidence="verify=False",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        import attack_graph

        eps = attack_graph.build_entry_points([crt, auth_f])
        self.assertTrue(any("Hidden subdomain" in ep["title"] for ep in eps))

    def test_wayback_finds_archived_sensitive_paths(self):
        class FakeResp:
            status_code = 200

            @staticmethod
            def json():
                return [
                    ["original"],
                    ["http://example.com/admin/dashboard"],
                    ["http://example.com/static/app.js"],
                ]

        self._patch(wayback.requests, "get", lambda url, timeout=25: FakeResp())
        found = _REAL_SCAN_WAYBACK(["example.com"])
        self.assertEqual(len(found), 1)
        self.assertIn("/admin", found[0].evidence)

    def test_live_target_ignored_when_disabled(self):
        self._patch(fetcher, "fetch_repo", lambda repo_url, github_token="": (self.tmp, "demo-smoke"))
        self._patch(fetcher, "list_repo_files", lambda local_path: ["a.py"])
        self._patch(fetcher, "cleanup_repo", lambda local_path: None)
        self._patch(deps, "scan_dependencies", lambda local_path: [])
        self._patch(secrets, "scan_secrets", lambda local_path, all_files: [])
        self._patch(code, "scan_code", lambda local_path, all_files: [])
        self._patch(exposure, "scan_exposure", lambda local_path, all_files: [])
        self._patch(config_audit, "scan_config", lambda local_path, all_files: [])
        self._patch(agent, "analyze", lambda repo_url, scan_result, model=None, live_target=None, entry_points=None: "report")
        self._patch(config, "ENABLE_LIVE_SCAN", False)

        import scanners.network as network_mod
        self._patch(network_mod, "scan_network", lambda target: (_ for _ in ()).throw(AssertionError("network should not run")))

        result = scan_service.scan_repository(self.repo_url, "", None, live_target="scanme.nmap.org")
        self.assertEqual(result["live_target"], "")
        self.assertNotIn("network", result["scanner_status"])
        self.assertTrue(any("ENABLE_LIVE_SCAN" in err for err in result["scan_errors"]))


if __name__ == "__main__":
    unittest.main()
