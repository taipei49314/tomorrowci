#!/usr/bin/env python3
"""Executable regressions for previously rejected release and Action behavior."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HistoricalRegressionTests(unittest.TestCase):
    def test_historical_publish_workflow_path_is_retired(self) -> None:
        self.assertFalse((ROOT / ".github/workflows/release.yml").exists())

        candidate = (ROOT / ".github/workflows/candidate.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", candidate)
        self.assertIn("permissions:\n  contents: read", candidate)
        for forbidden in (
            "contents: write",
            "packages: write",
            "softprops/action-gh-release",
            "gh release create",
            "docker push",
        ):
            self.assertNotIn(forbidden, candidate)

    def test_generated_consumer_invokes_an_immutable_action(self) -> None:
        template = (ROOT / "action/workflow-template.yml").read_text(encoding="utf-8")
        match = re.search(
            r"uses:\s*taipei49314/tomorrowci/action@([0-9a-f]{40})$",
            template,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(match, "generated workflow must pin the composite Action")
        self.assertNotIn("fixtures/python-runtime-break", template)
        self.assertNotIn("cargo build", template)

    def test_action_has_no_latest_run_fallback_and_uploads_exact_evidence(self) -> None:
        action = (ROOT / "action/action.yml").read_text(encoding="utf-8")
        self.assertIn("RUN_ID=$(echo \"$OUT\"", action)
        self.assertIn("if-no-files-found: error", action)
        self.assertIn("path: ${{ steps.scan.outputs.run_dir }}", action)
        self.assertNotRegex(action, r"find\s+.*\.tomorrowci/runs")
        self.assertNotRegex(action, r"ls\s+-[A-Za-z]*t.*\.tomorrowci/runs")

    def test_simulated_frontier_is_not_reported_as_observed(self) -> None:
        simulated = self._parse_frontier("SIMULATED")
        self.assertIn("TCI_FO=0", simulated)
        self.assertIn("TCI_OBSERVED_GRADE=0", simulated)

        observed = self._parse_frontier("OBSERVED")
        self.assertIn("TCI_FO=1", observed)
        self.assertIn("TCI_OBSERVED_GRADE=1", observed)

    def test_legacy_evidence_cannot_authorize_action_gate(self) -> None:
        completed = self._run_parser("OBSERVED", schema_version=0)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("legacy/pre-schema", completed.stderr)

    def _parse_frontier(self, grade: str) -> str:
        completed = self._run_parser(grade, schema_version=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout

    def _run_parser(self, grade: str, schema_version: int) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "frontier.json").write_text(
                json.dumps(
                    {
                        "observed": True,
                        "grade": grade,
                        "failure_signature": {"normalized_hash": "sha256:" + "1" * 64},
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "evidence_schema_version": schema_version,
                        "results": [
                            {"verdict": "BASELINE_PASS"},
                            {"verdict": "FUTURE_FAIL"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "checksums.txt").write_text(
                "# tomorrowci-checksums-v2\n", encoding="utf-8"
            )
            environment = os.environ.copy()
            environment["RUN_DIR"] = str(run_dir)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "action/parse-evidence.py")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            return completed


if __name__ == "__main__":
    unittest.main()
