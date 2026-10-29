"""Behavior controls for the opt-in Python trial adapter (no third-party deps)."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

SCRIPT = Path(__file__).with_name("python_trial_runner.py")
spec = importlib.util.spec_from_file_location("trial_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class TrialControls(unittest.TestCase):
    def execute(self, body, arguments=None, package="subject"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "subject.py").write_text("VALUE = 42\n", encoding="utf-8")
            (root / "test_example.py").write_text("import unittest\n" + body, encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPT), "--framework", "unittest",
                "--source-package", package, "--", *(arguments or ["test_example", "-v"])],
                cwd=root, text=True, capture_output=True)
            lines = [line for line in result.stdout.splitlines() if line.startswith(runner.PREFIX)]
            self.assertEqual(len(lines), 1, result.stdout + result.stderr)
            return result.returncode, json.loads(lines[0][len(runner.PREFIX):])

    def test_real_success_and_source_identity(self):
        code, s = self.execute("class Tests(unittest.TestCase):\n def test_ok(self): self.assertEqual(2+2,4)\n")
        self.assertEqual(code, 0)
        self.assertEqual(s["tests_run"], 1)
        self.assertEqual(s["source_origins"], {"subject": "subject.py"})
        self.assertTrue(s["coverage_valid"])

    def test_zero_tests_cannot_pass(self):
        code, s = self.execute("# no tests\n")
        self.assertEqual(code, 6)
        self.assertFalse(s["coverage_valid"])

    def test_partial_skip_cannot_pass(self):
        code, s = self.execute("class Tests(unittest.TestCase):\n def test_ok(self): pass\n @unittest.skip('missing API dependency')\n def test_api(self): pass\n")
        self.assertEqual(code, 6)
        self.assertEqual(s["skipped"], 1)

    def test_original_failure_is_preserved(self):
        code, s = self.execute("class Tests(unittest.TestCase):\n def test_bad(self): self.fail('original assertion')\n")
        self.assertEqual(code, 1)
        self.assertEqual(s["failed"], 1)

    def test_import_error_cannot_be_success(self):
        code, s = self.execute("import a_missing_module_for_trial_control\n")
        self.assertEqual(code, 1)
        self.assertEqual(s["errors"], 1)
        self.assertEqual(s["tests_run"], 0)
        self.assertEqual(s["collection_errors"], 1)
        self.assertFalse(s["coverage_valid"])

    def test_expected_failure_does_not_satisfy_strict_trial(self):
        code, s = self.execute("class Tests(unittest.TestCase):\n @unittest.expectedFailure\n def test_expected(self): self.fail('known')\n")
        self.assertEqual(code, 6)
        self.assertEqual(s["expected_failures"], 1)

    def test_installed_module_outside_checkout_rejected(self):
        code, s = self.execute("", package="json")
        self.assertEqual(code, 7)
        self.assertIn("outside checkout", s["gate_errors"][0])

    def test_invalid_test_arguments_emit_incomplete_receipt(self):
        code, s = self.execute("", arguments=["--does-not-exist"])
        self.assertEqual(code, 7)
        self.assertFalse(s["coverage_valid"])


class PytestReportControls(unittest.TestCase):
    def plugin(self):
        plugin = runner.PytestEvidence()
        plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid="test.py::case")]))
        plugin.pytest_sessionfinish(None, 0)
        return plugin

    def test_empty_reason_xpass_is_rejected(self):
        plugin = self.plugin()
        plugin.pytest_runtest_logreport(SimpleNamespace(nodeid="test.py::case", when="call",
            passed=True, failed=False, skipped=False, wasxfail=""))
        summary = plugin.summary(0)
        self.assertEqual(summary["unexpected_successes"], 1)
        self.assertIn("unexpected_successes=1", runner.coverage_errors(summary))

    def test_collection_skip_is_not_invisible(self):
        plugin = self.plugin()
        plugin.pytest_collectreport(SimpleNamespace(nodeid="test_missing_api.py", failed=False, skipped=True))
        self.assertIn("skipped=1", runner.coverage_errors(plugin.summary(0)))

    def test_setup_failure_does_not_count_as_test_body_execution(self):
        plugin = self.plugin()
        plugin.pytest_runtest_logreport(SimpleNamespace(nodeid="test.py::case", when="setup",
            passed=False, failed=True, skipped=False))
        summary = plugin.summary(1)
        self.assertEqual(summary["tests_run"], 0)
        self.assertEqual(summary["errors"], 1)
        self.assertIn("no executed tests", runner.coverage_errors(summary))


if __name__ == "__main__":
    unittest.main(verbosity=2)
