#!/usr/bin/env python3
"""Run an explicitly selected Python trial; reject empty/skipped coverage.

Copy this file into the disposable target and invoke it inside the sandbox.
It is an opt-in test adapter, not an independent verifier of hostile tests.
Original unittest/pytest assertions and their nonzero outcomes are preserved.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

PREFIX = "TOMORROWCI_TRIAL_SUMMARY="


def ids_hash(ids: list[str]) -> str:
    return hashlib.sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest()


def verify_sources(root: Path, packages: list[str]) -> dict[str, str]:
    """Reject a same-named installed distribution in place of the checkout."""
    root = root.resolve(strict=True)
    if not root.is_relative_to(Path.cwd().resolve()):
        raise ValueError("source root must stay inside the trial checkout")
    sys.path.insert(0, str(root))
    origins = {}
    for package in packages:
        spec = importlib.util.find_spec(package)
        if spec is None or spec.origin in (None, "built-in", "frozen"):
            raise ValueError(f"source package has no concrete checkout origin: {package}")
        origin = Path(spec.origin).resolve(strict=True)
        if not origin.is_relative_to(root):
            raise ValueError(f"source package resolves outside checkout: {package}")
        origins[package] = origin.relative_to(Path.cwd().resolve()).as_posix()
    return origins


class TrialResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_ids: list[str] = []

    def startTest(self, test):
        self.test_ids.append(test.id())
        super().startTest(test)


class TrialRunner(unittest.TextTestRunner):
    resultclass = TrialResult


def run_unittest(arguments: list[str]) -> dict:
    program = unittest.TestProgram(module=None, argv=["unittest", *arguments],
                                   testRunner=TrialRunner, exit=False)
    result = program.result
    # unittest creates a synthetic _FailedTest for an import/discovery error.
    # Its execution is not execution of the requested project's tests.
    actual_ids = [name for name in result.test_ids
                  if not name.startswith("unittest.loader._FailedTest.")]
    return {
        "collected": len(actual_ids),
        "tests_run": len(actual_ids),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "collection_errors": len(program.testLoader.errors),
        "test_ids_sha256": ids_hash(actual_ids),
        "framework_exit_code": 0 if result.wasSuccessful() else 1,
    }


class PytestEvidence:
    def __init__(self):
        self.items: list[str] = []
        self.calls: set[str] = set()
        self.failed: set[str] = set()
        self.errors: set[str] = set()
        self.skipped: set[str] = set()
        self.xfailed: set[str] = set()
        self.xpassed: set[str] = set()
        self.collection_errors: set[str] = set()
        self.finished = False

    def pytest_collection_finish(self, session):
        self.items = [item.nodeid for item in session.items]

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors.add(report.nodeid)
        elif report.skipped:
            self.skipped.add("collection:" + report.nodeid)

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.calls.add(report.nodeid)
        if report.skipped:
            if hasattr(report, "wasxfail"):
                self.xfailed.add(report.nodeid)
            else:
                self.skipped.add(report.nodeid)
        if report.failed:
            (self.failed if report.when == "call" else self.errors).add(report.nodeid)
        if report.passed and hasattr(report, "wasxfail"):
            self.xpassed.add(report.nodeid)

    def pytest_sessionfinish(self, session, exitstatus):
        self.finished = True

    def summary(self, exit_code: int) -> dict:
        return {
            "collected": len(self.items), "tests_run": len(self.calls),
            "failed": len(self.failed), "errors": len(self.errors),
            "skipped": len(self.skipped), "expected_failures": len(self.xfailed),
            "unexpected_successes": len(self.xpassed),
            "collection_errors": len(self.collection_errors),
            "test_ids_sha256": ids_hash(self.items),
            "framework_exit_code": exit_code,
            "session_finished": self.finished,
        }


def run_pytest(arguments: list[str]) -> dict:
    import pytest
    plugin = PytestEvidence()
    exit_code = int(pytest.main(arguments, plugins=[plugin]))
    return plugin.summary(exit_code)


def coverage_errors(summary: dict) -> list[str]:
    errors = []
    if summary["collected"] == 0 or summary["tests_run"] == 0:
        errors.append("no executed tests")
    for field in ("skipped", "expected_failures", "unexpected_successes", "collection_errors"):
        if summary[field]:
            errors.append(f"{field}={summary[field]}")
    if summary.get("session_finished", True) is not True:
        errors.append("test session did not finish")
    if (summary["framework_exit_code"] == 0
            and summary["tests_run"] != summary["collected"]):
        errors.append("not every selected test executed")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", choices=("unittest", "pytest"), required=True)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--source-package", action="append", required=True)
    parser.add_argument("test_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    test_args = args.test_args[1:] if args.test_args[:1] == ["--"] else args.test_args
    summary = {"schema_version": 1, "framework": args.framework}
    try:
        summary["source_origins"] = verify_sources(Path(args.source_root), args.source_package)
        summary.update((run_pytest if args.framework == "pytest" else run_unittest)(test_args))
        summary["gate_errors"] = coverage_errors(summary)
        summary["coverage_valid"] = not summary["gate_errors"]
        code = summary["framework_exit_code"] or (6 if summary["gate_errors"] else 0)
    except (Exception, SystemExit) as error:
        # unittest's argument parser can exit before creating a result too.
        summary.update(coverage_valid=False, gate_errors=[f"{type(error).__name__}: {error}"])
        code = 7
    summary["exit_code"] = code
    print(PREFIX + json.dumps(summary, sort_keys=True, separators=(",", ":")), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
