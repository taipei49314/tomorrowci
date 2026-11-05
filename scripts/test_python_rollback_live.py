#!/usr/bin/env python3
"""Live Docker regression for rollback verification, never host target execution.

All fixtures and raw receipts remain in a NEW --work-dir. These are synthetic
engineering controls, not evidence of a real upstream dependency regression.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path

from test_python_dependency_live import (
    IMAGE_PATTERN, digest, make_wheel, read_json, require, run_cli, utc_now, write_json,
)


def fixture(folder: Path, mode: str, image: str) -> Path:
    project = folder / "project"
    project.mkdir(parents=True)
    changes = []
    for name in ("tc-primary", "tc-secondary"):
        before = make_wheel(project, name, "1.0.0", module_source="VALUE = 1\n")
        broken = name == "tc-primary" or mode == "independent-failure"
        requires = ("tc-primary>=2",) if mode == "dependency-conflict" and name == "tc-secondary" else ()
        after = make_wheel(project, name, "2.0.0", requires=requires,
                           module_source=f"VALUE = {2 if broken else 1}\n")
        changes.append({"id": name, "name": name, "before": before, "after": after})
    if mode == "nothing-retained":
        changes = changes[:1]
    write_json(project / ".tomorrowci-dependencies.json", {
        "schema_version": 2, "ecosystem": "python",
        "runtime": {"version": "3.11", "container_image": image},
        "content_hash_algorithm": "sha256-file-v1", "baseline": {"set_id": "before"},
        "candidate": {"set_id": "after", "changes": changes}, "unchanged": [],
    })
    write_json(project / ".tomorrowci.yml", {
        "version": 1,
        "project": {"ecosystem": "python", "build_command": "auto",
                    "test_command": "python -m unittest test_target -v"},
        "baseline": {"runtime": "3.11", "dependencies": "locked"},
        "candidates": {"runtime": {"channels": ["stable"], "max_versions": 0, "versions": []},
                       "dependencies": {"latest_allowed": True, "prerelease": False}},
        "execution": {"max_scenarios": 2 if mode == "budget-exhaustion" else 16,
                      "timeout_seconds": 60, "reruns_on_failure": 3, "max_parallel": 1},
        "sandbox": {"engine": "docker", "network": "fetch-only", "memory_mb": 512,
                    "cpus": 1.0, "pids_limit": 128},
        "report": {"html": False, "json": True, "sarif": False},
    })
    (project / "requirements.txt").write_text("# Closure is declared in the manifest.\n", encoding="utf-8")
    (project / "test_target.py").write_text(
        "import unittest\nimport tc_primary\n"
        + ("import tc_secondary\n" if mode != "nothing-retained" else "")
        + "class UpgradeTest(unittest.TestCase):\n"
        + "    def test_original_commands(self):\n"
        + "        self.assertEqual(tc_primary.VALUE, 1, 'primary regression')\n"
        + ("        self.assertEqual(tc_secondary.VALUE, 1, 'independent secondary regression')\n"
           if mode != "nothing-retained" else ""), encoding="utf-8")
    return project


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    binary, output = args.binary.resolve(), args.work_dir.absolute()
    if not binary.is_file() or not IMAGE_PATTERN.fullmatch(args.image) or output.exists():
        parser.error("require existing binary, digest-pinned image, and new output directory")
    output.mkdir(parents=True)
    output = output.resolve()
    summary = {"kind": "synthetic_engineering_regression", "hostname": platform.node(),
               "execution_label": "HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL",
               "started_at": utc_now(), "binary_sha256": digest(binary.read_bytes()),
               "script_sha256": digest(Path(__file__).read_bytes()), "image": args.image,
               "host_target_execution": False, "cases": [], "status": "RUNNING"}
    write_json(output / "summary.json", summary)
    for mode in ("verified-repair", "independent-failure", "dependency-conflict", "nothing-retained", "budget-exhaustion"):
        print(f"[{mode}] scan, rollback, independent verification", flush=True)
        record = {"case": mode, "status": "FAIL"}
        folder = output / mode
        try:
            project = fixture(folder, mode, args.image)
            logs = folder / "commands"
            logs.mkdir()
            def call(label: str, argv: list[str]) -> dict:
                return run_cli(binary, argv, project, logs, label)
            scan = call("scan", ["scan", str(project), "--config", str(project / ".tomorrowci.yml")])
            runs = list((project / ".tomorrowci/runs").iterdir())
            require(len(runs) == 1, "expected one diagnosis run")
            diagnosis = runs[0]
            require(call("verify-diagnosis", ["verify", diagnosis.name])["exit_code"] == 0, "diagnosis is unverifiable")
            frozen = {str(p.relative_to(diagnosis)): digest(p.read_bytes()) for p in diagnosis.rglob("*") if p.is_file()}
            repair = folder / "repair"
            rollback = call("rollback", ["rollback", diagnosis.name, "--out", str(repair)])
            verification = call("verify-rollback", ["verify-rollback", diagnosis.name, "--out", str(repair)])
            require(frozen == {str(p.relative_to(diagnosis)): digest(p.read_bytes()) for p in diagnosis.rglob("*") if p.is_file()}, "rollback altered its diagnosis")
            reduction = read_json(diagnosis / "reduction.json")
            result = read_json(repair / "rollback-result.json") if repair.exists() else None
            record.update(run_id=diagnosis.name, reduction_status=reduction["status"],
                          scan_exit=scan["exit_code"], rollback_exit=rollback["exit_code"],
                          verification_exit=verification["exit_code"], rollback_result=result)
            if mode == "verified-repair":
                require(rollback["exit_code"] == verification["exit_code"] == 0, "repair did not verify")
                require(result["status"] == "VERIFIED_COMMANDS_PASS", "wrong repair status")
                request = read_json(repair / "rollback-request.json")
                require(request["rolled_back_change_ids"] == ["tc-primary"] and request["retained_change_ids"] == ["tc-secondary"], "incorrect complement")
                pins = (repair / "requirements.rollback.txt").read_text(encoding="utf-8")
                require("tc-primary==1.0.0" in pins and "tc-secondary==2.0.0" in pins, "repair loses harmless update")
                # Relocation must not invalidate content-bound evidence.
                moved = folder / "relocated-repair"
                shutil.copytree(repair, moved)
                require(call("verify-relocated", ["verify-rollback", diagnosis.name, "--out", str(moved)])["exit_code"] == 0, "relocation failed")
                for name in ("requirements.rollback.txt", "rollback-request.json", "rollback-result.json"):
                    path = moved / name
                    original = path.read_bytes()
                    if name.endswith(".txt"):
                        path.write_bytes(original.replace(b"tc-secondary==2.0.0", b"tc-secondary==1.0.0"))
                    else:
                        data = json.loads(original)
                        if name == "rollback-request.json":
                            data["retained_change_ids"] = []
                        else:
                            data["replay_attempt"] = 0
                        write_json(path, data)
                    require(call("tamper-" + name, ["verify-rollback", diagnosis.name, "--out", str(moved)])["exit_code"] != 0, "tampered repair accepted")
                    path.write_bytes(original)
                record_path = moved / "rollback-result.json"
                original = record_path.read_bytes()
                overstated = json.loads(original)
                overstated["scope"] = "All compatibility proven"
                write_json(record_path, overstated)
                require(call("tamper-scope", ["verify-rollback", diagnosis.name, "--out", str(moved)])["exit_code"] != 0, "overstated scope accepted")
                record_path.write_bytes(original)
                target = next((moved / ".tomorrowci/runs").iterdir()) / "workspace/test_target.py"
                target.write_text("# tests removed\n", encoding="utf-8")
                require(call("tamper-tests", ["verify-rollback", diagnosis.name, "--out", str(moved)])["exit_code"] != 0, "changed tests accepted")
                require(call("reuse-output", ["rollback", diagnosis.name, "--out", str(repair)])["exit_code"] != 0, "existing output overwritten")
            else:
                require(rollback["exit_code"] != 0 and verification["exit_code"] != 0, "invalid repair was accepted")
                require(not (repair / "requirements.rollback.txt").exists(), "unverified repair pins published")
                if mode == "budget-exhaustion":
                    require(reduction["status"] == "INCONCLUSIVE" and not repair.exists(), "incomplete diagnosis proposed repair")
                else:
                    require(reduction["status"] == "PROVEN_MINIMAL", "fixture failed to diagnose stable original failure")
                    expected = "NO_RETAINED_UPDATES" if mode == "nothing-retained" else "VALIDATION_FAILED"
                    require(result["status"] == expected, "wrong rejection status")
                    if mode != "nothing-retained":
                        validation = read_json(repair / ".tomorrowci/runs" / result["validation_run_id"] / "run.json")
                        candidate = next(r for r in validation["results"] if r["scenario_id"] == "rollback-validation")
                        require(candidate["verdict"] == ("BLOCKED" if mode == "dependency-conflict" else "FUTURE_FAIL"), "wrong repair failure reason")
            record["status"] = "PASS"
        except (AssertionError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
            record["error"] = f"{type(error).__name__}: {error}"
        summary["cases"].append(record)
        write_json(folder / "assertions.json", record)
        write_json(output / "summary.json", summary)
        print(f"[{mode}] {record['status']}: {record.get('error', 'receipt assertions satisfied')}", flush=True)
    summary["finished_at"] = utc_now()
    summary["status"] = "PASS" if all(c["status"] == "PASS" for c in summary["cases"]) else "FAIL"
    write_json(output / "summary.json", summary)
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
