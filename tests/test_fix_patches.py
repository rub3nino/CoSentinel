import os
import tempfile
import unittest

from models import Finding, Severity
import fix_patches
from fix_patches import apply_unified_diff, attach_fix_patches, issue_name, validate_patch


class FixPatchesTest(unittest.TestCase):
    def test_issue_name_strips_prefix(self):
        self.assertEqual(issue_name("docker-compose: Public bind on all interfaces"), "Public bind on all interfaces")
        self.assertEqual(issue_name("Generic Secret detected"), "Generic Secret")

    def test_exposure_docker_compose_line_fix(self):
        original = "services:\n  web:\n    ports:\n      - '0.0.0.0:8080:8080'\n"
        finding = Finding(
            id="EXP-001",
            severity=Severity.HIGH,
            category="exposure",
            title="docker-compose: Public bind on all interfaces",
            description="x",
            file_path="docker-compose.yml",
            line_number=4,
            evidence="0.0.0.0:8080",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        attach_fix_patches("", [finding])  # won't read file
        # attach needs local_path — test propose via attach on tmp
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "docker-compose.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)
            attach_fix_patches(tmp, [finding])
        self.assertTrue(finding.auto_fixable)
        self.assertIn("127.0.0.1", finding.fix_patch)
        applied = apply_unified_diff(original, finding.fix_patch)
        self.assertIn("127.0.0.1:8080", applied)
        self.assertNotIn("0.0.0.0", applied)

    def test_debug_mode_flask_config_line(self):
        original = 'app.config["DEBUG"] = True\n'
        finding = Finding(
            id="CODE-001",
            severity=Severity.MEDIUM,
            category="code",
            title="Debug Mode",
            description="x",
            file_path="app.py",
            line_number=1,
            evidence='["DEBUG"] = True',
            fix_suggestion="fix",
            auto_fixable=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as fh:
                fh.write(original)
            attach_fix_patches(tmp, [finding])
        self.assertTrue(finding.auto_fixable)
        applied = apply_unified_diff(original, finding.fix_patch)
        self.assertIn("False", applied)

    def test_invalid_patch_not_marked_fixable(self):
        finding = Finding(
            id="CODE-999",
            severity=Severity.MEDIUM,
            category="code",
            title="Eval Usage",
            description="x",
            file_path="app.py",
            line_number=1,
            evidence="eval(",
            fix_suggestion="fix",
            auto_fixable=False,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as fh:
                fh.write("eval('1')\n")
            attach_fix_patches(tmp, [finding])
        self.assertFalse(finding.auto_fixable)
        self.assertIsNone(finding.fix_patch)

    def test_validate_rejects_noop_patch(self):
        original = "hello\n"
        patch = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n hello\n"
        self.assertFalse(validate_patch(original, patch))


if __name__ == "__main__":
    unittest.main()
