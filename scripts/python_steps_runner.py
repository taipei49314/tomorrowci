#!/usr/bin/env python3
"""Run an explicit ordered Python test plan inside the existing sandbox.

Output and optional pytest counts are cooperative diagnostics, not test
attestation. This runner does not change the original framework's exit status.
"""
from __future__ import annotations

import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time

PREFIX = "TOMORROWCI_STEPS_SUMMARY="
PLAN_NAME = ".tomorrowci-steps.json"
MAX_PLAN_BYTES = 262144
MAX_STEPS = 64
MAX_LINE_BYTES = 16384
COUNT_KEYS = ("passed", "failed", "errors", "skipped", "xfailed", "xpassed", "deselected")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def validate_steps(steps: object) -> list[list[str]]:
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError("steps must contain 1 to 64 argv lists")
    for argv in steps:
        if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
            raise ValueError("each step must be a nonempty argv list of at most 128 arguments")
        if any(not isinstance(arg, str) or not arg or len(arg) > 8192
               or any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in argv):
            raise ValueError("step arguments must be nonempty bounded strings without control characters")
        if argv[0] not in ("python", "python3", "pytest"):
            raise ValueError("steps support python, python3 or pytest commands only")
        if argv[0] in ("python", "python3") and len(argv) < 2:
            raise ValueError("a Python step needs a module, script or interpreter argument")
    return steps


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate plan key: " + key)
        result[key] = value
    return result


def load_plan(path: Path) -> list[list[str]]:
    with path.open("rb") as stream:
        data = stream.read(MAX_PLAN_BYTES + 1)
    if len(data) > MAX_PLAN_BYTES:
        raise ValueError("step plan exceeds 256 KiB")
    plan = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "steps"} \
            or type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("expected step plan schema_version 1")
    return validate_steps(plan["steps"])


def execution_argv(argv: list[str]) -> list[str]:
    if argv[0] == "pytest":
        return [sys.executable, "-m", "pytest", *argv[1:]]
    return [sys.executable, *argv[1:]]


def direct_pytest(argv: list[str]) -> bool:
    return argv[0] == "pytest" or argv[:3] in (
        ["python", "-m", "pytest"], ["python3", "-m", "pytest"])


def terminal_counts(line: str) -> dict[str, int] | None:
    line = ANSI.sub("", line).strip().strip("=").strip()
    match = re.fullmatch(r"(.+?) in [0-9]+(?:\.[0-9]+)?s(?: \([0-9:]+\))?", line)
    if not match:
        return None
    counts = dict.fromkeys(COUNT_KEYS, 0)
    if match[1] == "no tests ran":
        return counts
    seen = set()
    for part in match[1].split(", "):
        item = re.fullmatch(r"([0-9]{1,20}) (passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)", part)
        if not item:
            return None
        key = {"error": "errors", "warning": "warnings"}.get(item[2], item[2])
        number = int(item[1])
        if key in seen or number > (1 << 64) - 1:
            return None
        seen.add(key)
        if key in counts:
            counts[key] = number
    return counts if seen.intersection(COUNT_KEYS) else None


class SummaryLines:
    """Retain at most one short line and one candidate, never the raw stream."""
    def __init__(self):
        self.pending = bytearray()
        self.dropping = False
        self.oversized = False
        self.candidates = 0
        self.counts = None
        self.last_is_summary = False

    def line(self, value: bytes):
        text = value.decode("utf-8", errors="replace")
        if not ANSI.sub("", text).strip():
            return
        self.last_is_summary = False
        counts = terminal_counts(text)
        if counts is not None:
            self.candidates += 1
            self.counts = counts
            self.last_is_summary = True

    def feed(self, chunk: bytes):
        for piece in chunk.splitlines(keepends=True):
            ending = piece.endswith((b"\n", b"\r"))
            if not self.dropping:
                if len(self.pending) + len(piece) > MAX_LINE_BYTES:
                    self.pending.clear()
                    self.dropping = True
                    self.oversized = True
                else:
                    self.pending.extend(piece)
            if ending:
                if not self.dropping:
                    self.line(bytes(self.pending))
                self.pending.clear()
                self.dropping = False

    def finish(self):
        if self.pending and not self.dropping:
            self.line(bytes(self.pending))
        self.pending.clear()


def drain(pipe, destination, parser: SummaryLines, errors: list[str]):
    forwarding = True
    try:
        while chunk := pipe.read1(8192):
            parser.feed(chunk)
            if forwarding:
                try:
                    destination.write(chunk)
                    destination.flush()
                except (OSError, ValueError) as exc:
                    errors.append(type(exc).__name__)
                    forwarding = False  # Keep draining so a child cannot deadlock.
        parser.finish()
    except (OSError, ValueError) as exc:
        errors.append(type(exc).__name__)
    finally:
        pipe.close()


def run_step(index: int, argv: list[str]) -> dict:
    print("\nTomorrowCI step " + str(index) + ": " + json.dumps(argv, ensure_ascii=True), flush=True)
    start = time.monotonic()
    result = dict(index=index, argv=argv, status="completed", exit_code=None,
                  duration_ms=0, counts=None, counts_source=None)
    try:
        process = subprocess.Popen(execution_argv(argv), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        print("Could not start step: " + str(exc)[:2000], file=sys.stderr, flush=True)
        result.update(status="start_error", exit_code=127,
                      duration_ms=round((time.monotonic() - start) * 1000))
        return result
    parsers = [SummaryLines(), SummaryLines()]
    errors: list[str] = []
    threads = [threading.Thread(target=drain, args=(pipe, destination, parser, errors))
               for pipe, destination, parser in zip(
                   (process.stdout, process.stderr), (sys.stdout.buffer, sys.stderr.buffer), parsers)]
    for thread in threads:
        thread.start()
    code = process.wait()
    for thread in threads:
        thread.join()
    result.update(exit_code=code, duration_ms=round((time.monotonic() - start) * 1000))
    candidates = [parser for parser in parsers if parser.candidates]
    if direct_pytest(argv) and not errors and not any(p.oversized for p in parsers) \
            and sum(p.candidates for p in parsers) == 1 and candidates[0].last_is_summary:
        result.update(counts=candidates[0].counts, counts_source="pytest-terminal-summary")
    if errors:
        print("Step output forwarding was incomplete: " + ", ".join(errors), file=sys.stderr, flush=True)
    return result


def main() -> int:
    try:
        steps = load_plan(Path(PLAN_NAME))
    except (OSError, ValueError) as exc:
        print("Invalid Python step plan: " + str(exc)[:2000], file=sys.stderr, flush=True)
        return 2
    records = []
    final_code = 0
    for index, argv in enumerate(steps, 1):
        if final_code:
            records.append(dict(index=index, argv=argv, status="not_run", exit_code=None,
                                duration_ms=0, counts=None, counts_source=None))
            continue
        record = run_step(index, argv)
        records.append(record)
        code = record["exit_code"]
        final_code = code if code >= 0 else 128 - code
    summary = dict(schema_version=1, python_version=platform.python_version(),
                   steps=records, exit_code=final_code)
    print("\n" + PREFIX + json.dumps(summary, sort_keys=True, separators=(",", ":")), flush=True)
    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
