#!/usr/bin/env python3
"""Exercise subprocess ordering, original exits and conservative diagnostics."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import python_steps_runner as runner


class StepsRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def script(self, name, source):
        (self.root / name).write_text(source, encoding="utf-8")

    def run_plan(self, steps):
        (self.root / runner.PLAN_NAME).write_text(
            json.dumps({"schema_version": 1, "steps": steps}), encoding="utf-8")
        process = subprocess.run([sys.executable, str(Path(runner.__file__).resolve())],
                                 cwd=self.root, capture_output=True, timeout=20)
        markers = [line[len(runner.PREFIX):] for line in process.stdout.decode("utf-8").splitlines()
                   if line.startswith(runner.PREFIX)]
        self.assertEqual(len(markers), 1, process.stderr.decode("utf-8", errors="replace"))
        return process, json.loads(markers[0])

    def test_two_steps_use_fresh_processes_same_workspace_and_exact_arguments(self):
        self.script("first.py", "import os\nfrom pathlib import Path\nPath('first.pid').write_text(str(os.getpid()))\n")
        self.script("second file.py", "import json, os, sys\nfrom pathlib import Path\n"
                    "assert int(Path('first.pid').read_text()) != os.getpid()\n"
                    "Path('args.json').write_text(json.dumps(sys.argv[1:]))\n"
                    "print('stdout-without-newline', end='')\nprint('stderr intact', file=sys.stderr)\n")
        steps = [["python", "first.py"], ["python3", "second file.py", "argument with spaces"]]
        process, summary = self.run_plan(steps)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["schema_version"], 1)
        self.assertRegex(summary["python_version"], r"^3\.\d+\.\d+")
        self.assertEqual([step["argv"] for step in summary["steps"]], steps)
        self.assertEqual([step["status"] for step in summary["steps"]], ["completed", "completed"])
        self.assertEqual(json.loads((self.root / "args.json").read_text()), ["argument with spaces"])
        self.assertIn(b"stdout-without-newline\n" + runner.PREFIX.encode(), process.stdout.replace(b"\r\n", b"\n"))
        self.assertIn(b"stderr intact", process.stderr)
        for step in summary["steps"]:
            self.assertEqual(step["exit_code"], 0)
            self.assertGreaterEqual(step["duration_ms"], 0)
            self.assertIsNone(step["counts"])
            self.assertIsNone(step["counts_source"])

    def test_failure_preserves_exit_and_does_not_start_later_step(self):
        self.script("fails.py", "raise SystemExit(7)\n")
        self.script("later.py", "from pathlib import Path\nPath('must-not-exist').touch()\n")
        process, summary = self.run_plan([["python", "fails.py"], ["python", "later.py"]])
        self.assertEqual(process.returncode, 7)
        self.assertEqual(summary["exit_code"], 7)
        self.assertEqual(summary["steps"][0]["exit_code"], 7)
        self.assertEqual(summary["steps"][1]["status"], "not_run")
        self.assertIsNone(summary["steps"][1]["exit_code"])
        self.assertEqual(summary["steps"][1]["duration_ms"], 0)
        self.assertFalse((self.root / "must-not-exist").exists())

    def test_missing_script_keeps_python_failure_and_stops(self):
        process, summary = self.run_plan([["python", "missing.py"], ["python", "also-missing.py"]])
        self.assertEqual(process.returncode, 2)
        self.assertEqual(summary["steps"][0]["status"], "completed")
        self.assertEqual(summary["steps"][0]["exit_code"], 2)
        self.assertEqual(summary["steps"][1]["status"], "not_run")
        self.assertIn(b"missing.py", process.stderr)

    def test_spawn_error_is_distinct_and_returns_127(self):
        with mock.patch.object(runner.subprocess, "Popen", side_effect=FileNotFoundError("missing interpreter")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = runner.run_step(1, ["python", "test.py"])
        self.assertEqual(result["status"], "start_error")
        self.assertEqual(result["exit_code"], 127)
        self.assertIsNone(result["counts"])

    def test_direct_pytest_counts_are_separate_and_keep_original_argv(self):
        # A local module provides deterministic pytest terminal-output fixtures.
        self.script("pytest.py", "print('================ 941 passed, 2 skipped, 1 warning in 0.25s ================')\n")
        steps = [["python", "-m", "pytest"], ["pytest", "--cov=subject", "--cov-report=xml"]]
        process, summary = self.run_plan(steps)
        self.assertEqual(process.returncode, 0)
        self.assertNotIn("counts", summary)  # No invented total or unique-test count.
        for step, argv in zip(summary["steps"], steps):
            self.assertEqual(step["argv"], argv)
            self.assertEqual(step["counts"], dict(passed=941, failed=0, errors=0, skipped=2,
                                                   xfailed=0, xpassed=0, deselected=0))
            self.assertEqual(step["counts_source"], "pytest-terminal-summary")

    def test_failed_pytest_summary_remains_diagnostic_without_masking_exit(self):
        self.script("pytest.py", "print('==== 1 failed, 2 passed, 1 error in 0.10s ====')\nraise SystemExit(1)\n")
        process, summary = self.run_plan([["python3", "-m", "pytest"]])
        self.assertEqual(process.returncode, 1)
        self.assertEqual(summary["steps"][0]["counts"]["errors"], 1)
        self.assertEqual(summary["steps"][0]["counts"]["failed"], 1)
        self.assertEqual(summary["steps"][0]["exit_code"], 1)

    def test_ambiguous_malformed_or_nonterminal_counts_stay_unknown(self):
        outputs = ["2 passed in 0.1s\n3 passed in 0.2s\n",
                   "2 passed, 3 passed in 0.1s\n",
                   "2 passed in 0.1s\ntrailing output\n",
                   "unknown report format\n"]
        for output in outputs:
            with self.subTest(output=output):
                self.script("pytest.py", "import sys\nsys.stdout.write(" + repr(output) + ")\n")
                process, summary = self.run_plan([["python", "-m", "pytest"]])
                self.assertEqual(process.returncode, 0)
                self.assertIsNone(summary["steps"][0]["counts"])
                self.assertIsNone(summary["steps"][0]["counts_source"])

    def test_custom_script_cannot_be_mislabelled_as_pytest_counts(self):
        self.script("custom.py", "print('941 passed in 0.1s')\n")
        process, summary = self.run_plan([["python", "custom.py"]])
        self.assertEqual(process.returncode, 0)
        self.assertIsNone(summary["steps"][0]["counts"])

    def test_large_output_is_forwarded_but_overlong_lines_make_counts_unknown(self):
        self.script("pytest.py", "import sys\nsys.stdout.write('x' * 2000000 + '\\n')\nprint('941 passed in 0.1s')\n")
        process, summary = self.run_plan([["python", "-m", "pytest"]])
        self.assertEqual(process.returncode, 0)
        self.assertIn(b"x" * 2000000 + b"\n", process.stdout.replace(b"\r\n", b"\n"))
        self.assertIsNone(summary["steps"][0]["counts"])
        parser = runner.SummaryLines()
        for _ in range(300):
            parser.feed(b"x" * 8192)
            self.assertLessEqual(len(parser.pending), runner.MAX_LINE_BYTES)
        parser.feed(b"\n941 passed in 0.1s\n")
        self.assertTrue(parser.oversized)

    def test_signal_exit_uses_portable_top_level_code_and_original_step_code(self):
        step = dict(index=1, argv=["python", "test.py"], status="completed", exit_code=-9,
                    duration_ms=1, counts=None, counts_source=None)
        output = io.StringIO()
        with mock.patch.object(runner, "load_plan", return_value=[step["argv"], ["pytest"]]), \
                mock.patch.object(runner, "run_step", return_value=step), contextlib.redirect_stdout(output):
            self.assertEqual(runner.main(), 137)
        summary = json.loads(output.getvalue().strip()[len(runner.PREFIX):])
        self.assertEqual(summary["exit_code"], 137)
        self.assertEqual(summary["steps"][0]["exit_code"], -9)
        self.assertEqual(summary["steps"][1]["status"], "not_run")

    def test_invalid_or_oversized_plan_is_rejected_before_execution(self):
        examples = ['{"schema_version":1,"schema_version":1,"steps":[["pytest"]]}',
                    '{"schema_version":true,"steps":[["pytest"]]}',
                    '{"schema_version":1,"steps":[["sh","test.sh"]]}',
                    '{"schema_version":1,"steps":[]}', " " * (runner.MAX_PLAN_BYTES + 1)]
        for data in examples:
            with self.subTest(data=data[:100]):
                path = self.root / runner.PLAN_NAME
                path.write_text(data, encoding="utf-8")
                with self.assertRaises(ValueError):
                    runner.load_plan(path)

    def test_terminal_parser_handles_ansi_zero_tests_and_rejects_overflow(self):
        counts = runner.terminal_counts("\x1b[32m=== 1 passed, 1 xfailed, 2 xpassed, 3 deselected in 120.10s (0:02:00) ===\x1b[0m")
        self.assertEqual(counts, dict(passed=1, failed=0, errors=0, skipped=0,
                                      xfailed=1, xpassed=2, deselected=3))
        self.assertEqual(runner.terminal_counts("no tests ran in 0.01s"), dict.fromkeys(runner.COUNT_KEYS, 0))
        self.assertIsNone(runner.terminal_counts("18446744073709551616 passed in 0.1s"))


if __name__ == "__main__":
    unittest.main()
