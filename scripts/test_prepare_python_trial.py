#!/usr/bin/env python3
"""Preparation must preserve original source and never import target code."""
import json
import tempfile
import unittest
from pathlib import Path

import prepare_python_trial as trial


class PrepareTrialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source with spaces"
        self.source.mkdir()
        trial.git(self.source, "init", "--template=")
        trial.git(self.source, "config", "user.name", "Trial test")
        trial.git(self.source, "config", "user.email", "test@example.invalid")
        (self.source / "subject.py").write_text("raise RuntimeError('target must not execute during preparation')\n", encoding="utf-8")
        (self.source / "tests").mkdir()
        (self.source / "tests/test_subject.py").write_text("import subject\n", encoding="utf-8")
        self.commit()
        self.options = dict(source=self.source, output=self.base / "output with spaces",
                            baseline="3.12", candidate="3.14", framework="unittest",
                            source_root=".", packages=["subject"],
                            test_args=["discover", "-s", "tests", "-v"], stdlib_only=True)

    def commit(self):
        trial.git(self.source, "add", ".")
        trial.git(self.source, "commit", "-m", "fixture")

    def test_clean_snapshot_records_exact_source_without_running_it(self):
        before = trial.git(self.source, "rev-parse", "HEAD")
        result = trial.prepare(**self.options)
        output = self.options["output"]
        self.assertEqual(result["status"], "PREPARED_NOT_EXECUTED")
        self.assertFalse(result["target_code_executed"])
        self.assertEqual(trial.git(output, "rev-parse", "HEAD"), before)
        self.assertEqual((output / "subject.py").read_bytes(), (self.source / "subject.py").read_bytes())
        self.assertEqual(trial.git(self.source, "status", "--porcelain=v1"), "")
        config = json.loads((output / ".tomorrowci.yml").read_text())
        self.assertEqual(config["candidates"]["runtime"]["versions"], ["3.14"])
        self.assertIn("--source-package subject -- discover -s tests -v", config["project"]["test_command"])
        self.assertFalse((self.source / ".tomorrowci.yml").exists())

    def test_pytest_copies_supplied_requirements_without_resolving(self):
        requirements = self.base / "frozen.txt"
        requirements.write_text("pytest==7.4.4\n", encoding="utf-8")
        self.options.update(framework="pytest", stdlib_only=False, requirements=requirements,
                            test_args=["-q", "tests/test_subject.py"])
        result = trial.prepare(**self.options)
        self.assertFalse(result["dependencies_resolved"])
        self.assertEqual((self.options["output"] / "requirements.txt").read_bytes(), requirements.read_bytes())

    def test_existing_output_is_never_overwritten(self):
        output = self.options["output"]
        output.mkdir()
        sentinel = output / "important.txt"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            trial.prepare(**self.options)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_subdirectory_source_is_rejected_before_creating_output(self):
        self.options["source"] = self.source / "tests"
        with self.assertRaisesRegex(ValueError, "checkout root"):
            trial.prepare(**self.options)
        self.assertFalse(self.options["output"].exists())

    def test_dirty_or_untracked_source_is_rejected(self):
        for path in (self.source / "untracked.txt", self.source / "subject.py"):
            original = path.read_bytes() if path.exists() else None
            path.write_text("changed", encoding="utf-8")
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "must be clean"):
                trial.prepare(**self.options)
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)
        self.assertFalse(self.options["output"].exists())

    def test_dependencies_are_an_explicit_choice(self):
        for changes in ({"stdlib_only": False}, {"framework": "pytest"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                trial.prepare(**{**self.options, **changes})
        self.assertFalse(self.options["output"].exists())

    def test_invalid_versions_commands_and_root_create_no_output(self):
        variants = [{"baseline": "3.012"}, {"candidate": "3.12"}, {"candidate": "3.14-slim"},
                    {"source_root": "../"}, {"source_root": "C:/"}, {"test_args": []},
                    {"test_args": ["tests/file with space.py"]}, {"packages": []}, {"timeout": 0},
                    {"output": self.source / "trial"}]
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                trial.prepare(**{**self.options, **changes})
        self.assertFalse(self.options["output"].exists())

    def test_existing_trial_configuration_is_not_reinterpreted(self):
        (self.source / ".tomorrowci-dependencies.json").write_text("{}")
        self.commit()
        with self.assertRaisesRegex(ValueError, "already contains"):
            trial.prepare(**self.options)
        self.assertFalse(self.options["output"].exists())

    def test_submodule_is_rejected_before_checkout(self):
        head = trial.git(self.source, "rev-parse", "HEAD")
        trial.git(self.source, "update-index", "--add", "--cacheinfo", "160000," + head + ",submodule")
        trial.git(self.source, "commit", "-m", "submodule fixture")
        with self.assertRaisesRegex(ValueError, "Symlinks and submodules"):
            trial.prepare(**self.options)
        self.assertFalse(self.options["output"].exists())

    def test_symlink_is_rejected_before_checkout(self):
        blob = trial.git(self.source, "rev-parse", "HEAD:subject.py")
        trial.git(self.source, "update-index", "--add", "--cacheinfo", "120000," + blob + ",link")
        trial.git(self.source, "commit", "-m", "symlink fixture")
        with self.assertRaisesRegex(ValueError, "Symlinks and submodules"):
            trial.prepare(**self.options)
        self.assertFalse(self.options["output"].exists())

    def test_cli_accepts_options_after_source_and_requires_separator(self):
        argv = [str(self.source), "--output", str(self.options["output"]),
                "--baseline", "3.12", "--candidate", "3.14", "--framework", "unittest",
                "--source-package", "subject", "--stdlib-only"]
        self.assertEqual(trial.main(argv), 2)
        self.assertEqual(trial.main(argv + ["--", "discover", "-s", "tests", "-v"]), 0)


if __name__ == "__main__":
    unittest.main()
