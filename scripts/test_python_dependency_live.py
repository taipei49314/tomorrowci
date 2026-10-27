#!/usr/bin/env python3
"""Exercise wheel FETCH guards through the real CLI and Docker sandbox.

Requires a built CLI and an available digest-pinned Python 3.11 image with pip.
Uses only the standard library on the host. Generated target code is executed
only by `tomorrowci scan` inside Docker; never imported or run by this harness.
All inputs, command logs, raw CLI receipts, and summary.json stay in a NEW
--work-dir. These synthetic engineering regressions are not upstream adoption
or natural-break evidence. No existing case directory is modified.
Includes a complete-closure passing control and a two-scenario budget control:
one real failing update plus one harmless update must remain INCONCLUSIVE.

Example:
  python scripts/test_python_dependency_live.py --binary target/debug/tomorrowci \
      --work-dir /tmp/tomorrowci-wheel-guards --image python@sha256:<64-hex>
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASES = (
    "valid-closure-control",
    "metadata-name-mismatch",
    "direct-file-reference",
    "direct-https-reference",
    "missing-transitive-unselected-wheel",
    "budget-exhaustion",
    "runtime-image-mismatch",
)
IMAGE_PATTERN = re.compile(r"^(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}$")
DIAGNOSTICS = {
    "metadata-name-mismatch": "wheel identity differs from declared resolution:",
    "direct-file-reference": "direct-reference wheel dependencies are unsupported:",
    "direct-https-reference": "direct-reference wheel dependencies are unsupported:",
    "missing-transitive-unselected-wheel": "No matching distribution found for tc-transitive==1.0.0",
    "runtime-image-mismatch": "wheel runtime differs from declared resolution: expected 3.10, observed 3.11",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def make_wheel(
    project: Path,
    name: str,
    version: str,
    *,
    metadata_name: str | None = None,
    requires: tuple[str, ...] = (),
    requires_python: str = ">=3.11",
    module_source: str = 'VALUE = "stable"\n',
) -> dict[str, str]:
    """Write deterministic pure-Python wheel bytes, including a valid RECORD."""
    module = name.replace("-", "_")
    info = f"{module}-{version}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        f"Name: {metadata_name or name}\n"
        f"Version: {version}\n"
        f"Requires-Python: {requires_python}\n"
        + "".join(f"Requires-Dist: {item}\n" for item in requires)
        + "\nSynthetic TomorrowCI engineering regression fixture.\n"
    )
    files = {
        f"{module}/__init__.py": module_source.encode("utf-8"),
        f"{info}/METADATA": metadata.encode("utf-8"),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: tomorrowci-live-regression\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("ascii"),
    }
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, data in sorted(files.items()):
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        writer.writerow((path, "sha256=" + encoded.decode("ascii"), len(data)))
    writer.writerow((f"{info}/RECORD", "", ""))
    files[f"{info}/RECORD"] = record.getvalue().encode("utf-8")
    relative = f"wheels/{module}-{version}-py3-none-any.whl"
    output = project / relative
    output.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, data in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return {"version": version, "source": relative, "content_sha256": digest(output.read_bytes())}


def prepare_case(case_dir: Path, name: str, image: str) -> Path:
    project = case_dir / "project"
    project.mkdir(parents=True)
    runtime = "3.10" if name == "runtime-image-mismatch" else "3.11"
    transitive = make_wheel(project, "tc-transitive", "1.0.0", requires_python=f">={runtime}")
    requirements = ("tc-transitive==1.0.0",)
    metadata_name = None
    if name == "metadata-name-mismatch":
        metadata_name = "tc-other-name"
        requirements = ()
    elif name == "direct-file-reference":
        requirements = (f"tc-transitive @ file:///work/{transitive['source']}",)
    elif name == "direct-https-reference":
        requirements = (
            "tc-transitive @ https://example.invalid/tc_transitive-1.0.0-py3-none-any.whl",
        )
    module_source = 'from tc_transitive import VALUE\n'
    before = make_wheel(
        project, "tc-subject", "1.0.0", metadata_name=metadata_name,
        requires=requirements, requires_python=f">={runtime}", module_source=module_source,
    )
    after = make_wheel(
        project, "tc-subject", "2.0.0", metadata_name=metadata_name,
        requires=requirements, requires_python=f">={runtime}",
        module_source=module_source + ('VALUE = "broken"\n' if name == "budget-exhaustion" else ""),
    )
    unchanged = []
    if name in ("valid-closure-control", "budget-exhaustion", "runtime-image-mismatch"):
        unchanged.append({"id": "tc-transitive", "name": "tc-transitive", "artifact": transitive})
    changes = [{"id": "tc-subject", "name": "tc-subject", "before": before, "after": after}]
    if name == "budget-exhaustion":
        changes.append({
            "id": "tc-noise", "name": "tc-noise",
            "before": make_wheel(project, "tc-noise", "1.0.0"),
            "after": make_wheel(project, "tc-noise", "2.0.0"),
        })
    manifest = {
        "schema_version": 2,
        "ecosystem": "python",
        "runtime": {"version": runtime, "container_image": image},
        "content_hash_algorithm": "sha256-file-v1",
        "baseline": {"set_id": "before"},
        "candidate": {
            "set_id": "after",
            "changes": changes,
        },
        "unchanged": unchanged,
    }
    write_json(project / ".tomorrowci-dependencies.json", manifest)
    write_json(project / ".tomorrowci.yml", {
        "version": 1,
        "project": {
            "ecosystem": "python", "test_command": "python -m unittest test_target -v",
            "build_command": "auto",
        },
        "baseline": {"runtime": runtime, "dependencies": "locked"},
        "candidates": {
            "runtime": {"channels": ["stable"], "max_versions": 0, "versions": []},
            "dependencies": {"latest_allowed": True, "prerelease": False},
        },
        "execution": {
            "max_scenarios": 2 if name == "budget-exhaustion" else 4, "timeout_seconds": 60,
            "reruns_on_failure": 3, "max_parallel": 1,
        },
        "sandbox": {
            "engine": "docker", "network": "fetch-only", "memory_mb": 512,
            "cpus": 1.0, "pids_limit": 128,
        },
        "report": {"html": False, "json": True, "sarif": False},
    })
    # Detection only: the exact declared wheels are the installation authority.
    (project / "requirements.txt").write_text("# Exact wheel closure is declared in the manifest.\n", encoding="utf-8")
    (project / "test_target.py").write_text(
        '"""Synthetic target: executed only inside the CLI Docker sandbox."""\n'
        "import sys\n"
        "import unittest\n"
        "from pathlib import Path\n"
        "Path('target-was-executed.txt').write_text('sandbox test started\\n')\n"
        "import tc_subject\n\n"
        "class WheelClosureTest(unittest.TestCase):\n"
        "    def test_selected_closure(self):\n"
        "        self.assertEqual(sys.version_info[:2], (3, 11))\n"
        "        self.assertEqual(tc_subject.VALUE, 'stable')\n",
        encoding="utf-8",
    )
    write_json(case_dir / "fixture.json", {
        "kind": "synthetic_engineering_regression",
        "case": name,
        "declared_runtime": runtime,
        "expected_image_runtime": "3.11",
        "expected": (
            "FUTURE_FAIL_BUDGET_INCONCLUSIVE" if name == "budget-exhaustion"
            else "PASS" if name == "valid-closure-control" else "FETCH_BLOCKED"
        ),
        "expected_fetch_diagnostic": DIAGNOSTICS.get(name),
        "unselected_wheel": transitive if not unchanged else None,
        "manifest_sha256": digest((project / ".tomorrowci-dependencies.json").read_bytes()),
        "config_sha256": digest((project / ".tomorrowci.yml").read_bytes()),
    })
    return project


def run_cli(binary: Path, argv: list[str], cwd: Path, logs: Path, label: str) -> dict[str, Any]:
    """The only subprocess boundary: the trusted CLI, never a target interpreter."""
    command = [str(binary), *argv]
    started = utc_now()
    clock = time.monotonic()
    record: dict[str, Any] = {"argv": command, "cwd": str(cwd), "started_at": started}
    temporary = logs.parent / "temporary"
    temporary.mkdir(exist_ok=True)
    environment = os.environ.copy()
    overrides = {key: str(temporary) for key in ("TMP", "TEMP", "TMPDIR")}
    environment.update(overrides)
    record["environment_overrides"] = overrides
    with (logs / f"{label}.stdout.log").open("wb") as stdout, (logs / f"{label}.stderr.log").open("wb") as stderr:
        try:
            result = subprocess.run(
                command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=1200, check=False, shell=False, env=environment,
            )
            record.update(exit_code=result.returncode, timed_out=False)
        except subprocess.TimeoutExpired:
            record.update(exit_code=None, timed_out=True, error="CLI exceeded 1200 seconds")
        except OSError as error:
            record.update(exit_code=None, timed_out=False, error=str(error))
    record.update(finished_at=utc_now(), duration_seconds=round(time.monotonic() - clock, 3))
    for stream in ("stdout", "stderr"):
        path = logs / f"{label}.{stream}.log"
        record[f"{stream}_path"] = str(path)
        record[f"{stream}_sha256"] = digest(path.read_bytes())
    write_json(logs / f"{label}.json", record)
    return record


def check_network_and_commands(sc_dir: Path, *, unselected: str | None) -> None:
    phase = read_json(sc_dir / "fetch-phase.json")
    require(phase["network"] == "none", "FETCH container network must be none")
    require(read_json(sc_dir / "fetch-result.json")["network_used"] is False, "FETCH raw receipt records network use")
    replay = read_json(sc_dir / "replay.json")
    require(replay["engine"] == "docker", "receipt did not use Docker")
    require(replay["fetch_network"] == replay["test_network"] == "none", "replay permits network")
    commands = read_json(sc_dir / "fetch-commands.json")
    require(bool(commands), "missing FETCH commands")
    require(all(command["network"] is False for command in commands), "FETCH command permits network")
    installs = [command["argv"] for command in commands if "pip" in command["argv"] and "install" in command["argv"]]
    require(len(installs) == 1, "expected one pip installation command")
    install = installs[0]
    require(all(flag in install for flag in ("-I", "--isolated", "--no-index", "--ignore-installed")), "pip lacks offline isolation flags")
    require(not any(arg.startswith(("--find-links", "--extra-index-url", "--index-url")) or arg == "-f" for arg in install), "pip can search unselected sources")
    if unselected:
        require(f"/work/{unselected}" not in install, "unselected wheel was passed to pip")
        selected = read_json(sc_dir / "resolved-dependencies.json")["dependencies"]
        require(all(dep["source"] != unselected for dep in selected), "unselected wheel became declared")


def check_case(name: str, project: Path, run: Path, scan: dict[str, Any], verify: dict[str, Any]) -> dict[str, Any]:
    require(verify["exit_code"] == 0, "CLI verify did not accept the raw receipt")
    require(not scan["timed_out"], "scan timed out")
    manifest = read_json(run / "run.json")
    baselines = [scenario for scenario in manifest["plan"]["scenarios"] if scenario["is_baseline"]]
    require(len(baselines) == 1, "expected exactly one baseline scenario")
    baseline_id = baselines[0]["id"]
    baseline_results = [result for result in manifest["results"] if result["scenario_id"] == baseline_id]
    require(len(baseline_results) == 1, "expected one executed baseline result")
    reduction = read_json(run / "reduction.json")
    claims = read_json(run / "claims.json")["rows"]
    fixture = read_json(project.parent / "fixture.json")
    unselected = fixture["unselected_wheel"]
    if unselected:
        snapshot_wheel = run / "workspace" / unselected["source"]
        require(snapshot_wheel.is_file(), "unselected wheel was absent from the captured workspace")
        require(digest(snapshot_wheel.read_bytes()) == unselected["content_sha256"], "unselected wheel changed during capture")
    for result in manifest["results"]:
        check_network_and_commands(
            run / "scenarios" / result["scenario_id"],
            unselected=unselected["source"] if unselected else None,
        )
    sc_dir = run / "scenarios" / baseline_id
    attempts = read_json(sc_dir / "test-attempts.json")
    phase = read_json(sc_dir / "fetch-phase.json")
    raw = read_json(sc_dir / "fetch-result.json")
    if name == "valid-closure-control":
        require(scan["exit_code"] == 0, "valid closure scan failed")
        require(baseline_results[0]["verdict"] == "BASELINE_PASS", "valid closure baseline did not pass")
        require(len(manifest["results"]) == 2, "positive control did not execute baseline and candidate")
        for result in manifest["results"]:
            expected = "BASELINE_PASS" if result["scenario_id"] == baseline_id else "FUTURE_PASS"
            require(result["verdict"] == expected, "valid closure candidate did not pass")
            tests = read_json(run / "scenarios" / result["scenario_id"] / "test-attempts.json")
            require(tests["status"] == "completed" and len(tests["attempts"]) >= 1, "positive tests were not executed")
            require(all(item["exit_code"] == 0 and not item["timed_out"] for item in tests["attempts"]), "positive control has unsuccessful test attempts")
        require(phase["ok"] and raw["exit_code"] == 0, "positive FETCH failed")
        require(reduction["status"] == "ORIGINAL_PASSED", "passing candidate was misclassified by reduction")
    elif name == "budget-exhaustion":
        require(scan["exit_code"] == 0, "budget control scan did not complete")
        require(manifest["plan"]["budget_max"] == 2, "budget control did not retain its two-scenario limit")
        require(len(manifest["results"]) == 2, "budget control must execute only baseline and full candidate")
        require(baseline_results[0]["verdict"] == "BASELINE_PASS", "budget control baseline did not pass")
        require(attempts["status"] == "completed" and len(attempts["attempts"]) == 1, "budget baseline was not tested once")
        require(attempts["attempts"][0]["exit_code"] == 0 and not attempts["attempts"][0]["timed_out"], "budget baseline attempt failed")
        candidate = next(result for result in manifest["results"] if result["scenario_id"] != baseline_id)
        require(candidate["verdict"] == "FUTURE_FAIL", "budget control full candidate did not fail")
        candidate_dir = run / "scenarios" / candidate["scenario_id"]
        candidate_tests = read_json(candidate_dir / "test-attempts.json")
        require(candidate_tests["status"] == "completed" and len(candidate_tests["attempts"]) == 3, "full candidate lacks three failure attempts")
        require(all(item["exit_code"] not in (None, 0) and not item["timed_out"] for item in candidate_tests["attempts"]), "full candidate failed from timeout or did not consistently fail")
        failure_hashes = {item["failure"]["normalized_hash"] for item in candidate_tests["attempts"]}
        require(len(failure_hashes) == 1, "full candidate failure changed across attempts")
        diagnostic = (candidate_dir / "stderr.log").read_text(encoding="utf-8", errors="replace")
        require("AssertionError: 'broken' != 'stable'" in diagnostic, "budget control failed for an unrelated reason")
        for result in manifest["results"]:
            fetch = read_json(run / "scenarios" / result["scenario_id"] / "fetch-phase.json")
            require(fetch["ok"] and fetch["exit_code"] == 0 and not fetch["timed_out"], "budget control FETCH failed")
        require(reduction["status"] == "INCONCLUSIVE" and reduction["authority"] == "INCONCLUSIVE", "exhausted budget falsely proved minimality")
        require(sorted(reduction["original_change_ids"]) == ["tc-noise", "tc-subject"], "budget control lost an original update")
        require(sorted(change["id"] for change in reduction["minimal_changes"]) == ["tc-noise", "tc-subject"], "budget control reduced without subset evidence")
        require(len(reduction["probes"]) == 1 and sorted(reduction["probes"][0]["change_ids"]) == ["tc-noise", "tc-subject"], "budget control ran a subset beyond its limit")
        require(reduction["probes"][0]["verdict"] == "FAIL" and reduction["stable_failure_hash"] in failure_hashes, "budget control did not bind the observed stable failure")
        require(not reduction["addition_probes"] and not reduction["subtraction_probes"], "budget control invented necessity/irrelevance proof")
    else:
        require(scan["exit_code"] == 2, "blocked scan must exit 2")
        require(len(manifest["results"]) == 1, "candidate ran after blocked baseline")
        require(baseline_results[0]["verdict"] == "BLOCKED", "invalid closure was not BLOCKED")
        require(read_json(sc_dir / "result.json")["verdict"] == "BLOCKED", "scenario receipt contradicts BLOCKED")
        require(attempts["status"] == "not_run" and attempts["attempts"] == [], "target tests ran after invalid FETCH")
        require(not (sc_dir / "test-phase.json").exists(), "test phase exists after invalid FETCH")
        require(phase["ok"] is False and phase["timed_out"] is False, "expected explicit FETCH rejection, not timeout")
        require(isinstance(raw["exit_code"], int) and raw["exit_code"] != 0 and not raw["timed_out"], "no concrete unsuccessful FETCH process receipt")
        diagnostic = (sc_dir / "fetch-stdout.log").read_text(encoding="utf-8", errors="replace") + (sc_dir / "fetch-stderr.log").read_text(encoding="utf-8", errors="replace")
        require(DIAGNOSTICS[name] in diagnostic, f"FETCH failed for an unrelated reason; missing {DIAGNOSTICS[name]!r}")
        require(manifest["frontier"]["observed"] is False, "blocked baseline produced an observed frontier")
        require(reduction["status"] in ("BLOCKED", "INCONCLUSIVE"), "blocked baseline produced a passing/minimal reduction")
        # The reducer retains the original set in minimal_changes until it has
        # evidence. Only PROVEN_MINIMAL confers minimality; BLOCKED must retain
        # the original IDs and have no probe/necessity proof or failure hash.
        require(
            sorted(change["id"] for change in reduction["minimal_changes"])
            == sorted(reduction["original_change_ids"]),
            "blocked baseline reduced the original change set without evidence",
        )
        require(
            not reduction["probes"] and not reduction["addition_probes"]
            and not reduction["subtraction_probes"] and reduction["stable_failure_hash"] is None,
            "blocked baseline produced a reduction proof",
        )
        require(bool(claims) and all(row["status"] == "BLOCKED" for row in claims), "blocked scan made a false PASS claim")
        require(not any(project.rglob("target-was-executed.txt")), "target side-effect marker exists after blocked FETCH")
    return {
        "run_id": manifest["run_id"], "evidence_root": str(run),
        "baseline_verdict": baseline_results[0]["verdict"],
        "baseline_test_attempts": len(attempts["attempts"]),
        "fetch_network": phase["network"], "reduction_status": reduction["status"],
        "scan_exit": scan["exit_code"], "verify_exit": verify["exit_code"],
        "run_json_sha256": digest((run / "run.json").read_bytes()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True, help="new directory; existing paths are refused")
    parser.add_argument("--image", required=True, help="immutable Python 3.11 image digest (with pip)")
    args = parser.parse_args()
    binary = args.binary.resolve()
    output = args.work_dir.absolute()
    if not binary.is_file():
        parser.error(f"CLI binary does not exist: {binary}")
    if not IMAGE_PATTERN.fullmatch(args.image):
        parser.error("--image must be a sha256 digest or repository@sha256 digest, using 64 lowercase hex characters")
    if output.exists() or output.is_symlink():
        parser.error(f"--work-dir must not already exist: {output}")
    output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    summary: dict[str, Any] = {
        "schema_version": 1, "kind": "synthetic_engineering_regression",
        "execution_label": "HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL" if platform.node().upper() == "LAPTOP-01AGNPJU" else "LOCAL_NOT_EC_POOL",
        "hostname": platform.node(), "platform": platform.platform(),
        "started_at": utc_now(), "binary": str(binary),
        "binary_sha256": digest(binary.read_bytes()),
        "script_sha256": digest(Path(__file__).read_bytes()),
        "image": args.image, "expected_image_runtime": "3.11", "reruns_on_failure": 3,
        "host_target_execution": False, "cases": [], "status": "RUNNING",
    }
    write_json(output / "summary.json", summary)
    for name in CASES:
        case_dir = output / name
        case_record: dict[str, Any] = {"case": name, "status": "FAIL"}
        print(f"[{name}] scan + verify", flush=True)
        try:
            project = prepare_case(case_dir, name, args.image)
            logs = case_dir / "commands"
            logs.mkdir()
            scan = run_cli(binary, ["scan", str(project), "--config", str(project / ".tomorrowci.yml")], project, logs, "scan")
            runs_dir = project / ".tomorrowci" / "runs"
            runs = sorted(path for path in runs_dir.iterdir() if path.is_dir()) if runs_dir.is_dir() else []
            require(len(runs) == 1, f"expected one raw evidence run, found {len(runs)}; inspect scan logs")
            run = runs[0]
            # Always attempt independent verification before interpreting results.
            verify = run_cli(binary, ["verify", run.name], project, logs, "verify")
            case_record.update(check_case(name, project, run, scan, verify))
            case_record["status"] = "PASS"
        except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
            case_record["error"] = f"{type(error).__name__}: {error}"
        summary["cases"].append(case_record)
        write_json(case_dir / "assertions.json", case_record)
        write_json(output / "summary.json", summary)
        print(f"[{name}] {case_record['status']}: {case_record.get('error', 'receipt assertions satisfied')}", flush=True)
    summary["finished_at"] = utc_now()
    summary["status"] = "PASS" if all(case["status"] == "PASS" for case in summary["cases"]) else "FAIL"
    write_json(output / "summary.json", summary)
    print(f"{summary['status']}: {output / 'summary.json'}", flush=True)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
