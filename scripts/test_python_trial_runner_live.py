#!/usr/bin/env python3
"""Exercise the Python trial adapter with real pytest inside offline Docker.

Synthetic controls, not project compatibility observations. Host-side code only
generates fixtures, validates wheel metadata, and records Docker receipts.
"""
from __future__ import annotations

import argparse
import datetime as dt
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
import uuid
import zipfile

PREFIX = "TOMORROWCI_TRIAL_SUMMARY="
WHEEL_NAMES = {"pytest", "pluggy", "packaging", "iniconfig"}
CONTROLS = [
    ("pass", "def test_ok(): assert True\n", "trial_subject", 0,
     {"coverage_valid": True, "tests_run": 1, "failed": 0, "skipped": 0}),
    ("zero-tests", "VALUE = 1\n", "trial_subject", 5,
     {"coverage_valid": False, "tests_run": 0, "collected": 0}),
    ("importorskip", "import pytest\npytest.importorskip('tomorrowci_absent_control_module_71229')\ndef test_unreached(): assert False\n", "trial_subject", 5,
     {"coverage_valid": False, "tests_run": 0, "skipped": 1}),
    ("partial-skip", "import pytest\ndef test_ok(): assert True\n@pytest.mark.skip(reason='control')\ndef test_skip(): assert False\n", "trial_subject", 6,
     {"coverage_valid": False, "tests_run": 1, "collected": 2, "skipped": 1}),
    ("xfail-empty-reason", "import pytest\n@pytest.mark.xfail(reason='')\ndef test_xfail(): assert False\n", "trial_subject", 6,
     {"coverage_valid": False, "expected_failures": 1, "unexpected_successes": 0}),
    ("xpass-empty-reason", "import pytest\n@pytest.mark.xfail(reason='', strict=False)\ndef test_xpass(): assert True\n", "trial_subject", 6,
     {"coverage_valid": False, "expected_failures": 0, "unexpected_successes": 1}),
    ("assertion-failure", "def test_failure(): assert False, 'real assertion remains failed'\n", "trial_subject", 1,
     {"coverage_valid": True, "tests_run": 1, "failed": 1, "framework_exit_code": 1}),
    ("collection-error", "import tomorrowci_absent_control_module_71229\ndef test_unreached(): assert False\n", "trial_subject", 2,
     {"coverage_valid": False, "tests_run": 0, "collection_errors": 1}),
    ("wrong-source-origin", "def test_unreached(): assert False\n", "pytest", 7,
     {"coverage_valid": False}),
]

CONTAINER_RUNNER = r'''
from pathlib import Path
import json, os, platform, shutil, subprocess, sys
inputs=Path('/inputs'); work=Path('/work')
manifest=json.loads((inputs/'manifest.json').read_text())
name=sys.argv[1]
case=next(c for c in manifest['controls'] if c['name']==name)
print('CONTROL_RUNTIME='+json.dumps({'python':platform.python_version(),'platform':platform.platform()}),flush=True)
install=[sys.executable,'-I','-m','pip','--isolated','install','--no-index','--no-cache-dir','--ignore-installed','--no-compile','--target','/work/deps']
install += [str(inputs/'wheels'/w['filename']) for w in manifest['wheels']]
install += [w['name']+'=='+w['version'] for w in manifest['wheels']]
code=subprocess.call(install)
if code: raise SystemExit(code)
target=work/'case'; shutil.copytree(inputs/'cases'/name,target)
env=dict(os.environ, PYTHONPATH='/work/deps', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONDONTWRITEBYTECODE='1')
command=[sys.executable,str(inputs/'python_trial_runner.py'),'--framework','pytest','--source-package',case['source_package'],'--','-q','tests']
raise SystemExit(subprocess.call(command,cwd=target,env=env))
'''


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def select_wheels(wheelhouse: Path, destination: Path) -> list[dict]:
    selected = {}
    for wheel in sorted(wheelhouse.glob("*.whl")):
        if wheel.is_symlink() or not wheel.is_file():
            raise ValueError("wheel must be a regular non-symlink file")
        with zipfile.ZipFile(wheel) as archive:
            members = [i for i in archive.infolist() if i.filename.endswith(".dist-info/METADATA")]
            if len(members) != 1 or members[0].file_size > 1024 * 1024:
                raise ValueError("wheel has invalid metadata")
            metadata = BytesParser().parsebytes(archive.read(members[0]))
        name = re.sub(r"[-_.]+", "-", metadata["Name"]).lower()
        if name not in WHEEL_NAMES:
            continue
        if name in selected:
            raise ValueError("multiple wheel choices for " + name)
        if any("@" in item for item in metadata.get_all("Requires-Dist", [])):
            raise ValueError("direct references are not allowed")
        copied = destination / wheel.name
        shutil.copyfile(wheel, copied)
        selected[name] = dict(name=name, version=metadata["Version"], filename=wheel.name,
                              sha256=digest(copied), source=str(wheel.resolve()),
                              requires_dist=metadata.get_all("Requires-Dist", []))
        if digest(wheel) != selected[name]["sha256"]:
            raise ValueError("wheel changed during copy")
    if set(selected) != WHEEL_NAMES:
        raise ValueError("expected exactly pytest, pluggy, packaging, iniconfig")
    return [selected[name] for name in sorted(selected)]


def command(argv: list[str], directory: Path, name: str, records: list[dict], timeout: int = 180):
    started = timestamp()
    tick = time.monotonic()
    stdout = directory / (name + ".stdout.log")
    stderr = directory / (name + ".stderr.log")
    timed_out = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            completed = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout)
            code = completed.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    record = dict(argv=argv, started_at=started, finished_at=timestamp(),
                  duration_seconds=round(time.monotonic() - tick, 3), exit_code=code,
                  timed_out=timed_out, stdout=str(stdout), stderr=str(stderr),
                  stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
    records.append(record)
    return code, stdout.read_text(encoding="utf-8", errors="replace"), stderr.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", args.image):
        parser.error("--image must use an immutable digest")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    inputs = work / "inputs"
    inputs.mkdir()
    wheels_dir = inputs / "wheels"
    wheels_dir.mkdir()
    wrapper = Path(__file__).resolve().with_name("python_trial_runner.py")
    shutil.copyfile(wrapper, inputs / wrapper.name)
    (inputs / "container_runner.py").write_text(CONTAINER_RUNNER, encoding="utf-8")
    manifest = dict(created_at=timestamp(), kind="SYNTHETIC_PYTEST_ADAPTER_CONTROLS", image=args.image,
                    harness_sha256=digest(Path(__file__)), wrapper_sha256=digest(wrapper),
                    container_runner_sha256=digest(inputs / "container_runner.py"),
                    wheels=select_wheels(args.wheelhouse.resolve(), wheels_dir), controls=[])
    for name, text, package, exit_code, expected in CONTROLS:
        target = inputs / "cases" / name
        (target / "trial_subject").mkdir(parents=True)
        (target / "trial_subject" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
        (target / "tests").mkdir()
        test = target / "tests" / "test_control.py"
        test.write_text(text, encoding="utf-8")
        manifest["controls"].append(dict(name=name, source_package=package, expected_exit=exit_code,
                                          expected_summary=expected, test_sha256=digest(test)))
    write_json(inputs / "manifest.json", manifest)
    repo = Path(__file__).resolve().parents[1]
    receipt = dict(created_at=timestamp(), hostname=platform.node(),
                   source_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                   source_status=subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=repo, text=True),
                   kind=manifest["kind"], manifest_sha256=digest(inputs / "manifest.json"),
                   label="HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL", commands=[], controls=[])
    code, output, _ = command(["docker", "version", "--format", "{{json .}}"], work, "docker-version", receipt["commands"])
    if code != 0:
        write_json(work / "summary.json", receipt)
        return 1
    receipt["docker"] = json.loads(output)
    code, output, _ = command(["docker", "image", "inspect", args.image], work, "image-inspect", receipt["commands"])
    if code != 0:
        write_json(work / "summary.json", receipt)
        return 1
    receipt["image_inspect"] = json.loads(output)
    for selected in manifest["controls"]:
        name = selected["name"]
        destination = work / name
        destination.mkdir()
        run_key = uuid.uuid4().hex
        cidfile = destination / "container.cid"
        argv = ["docker", "run", "--rm", "--pull=never", "--cidfile", str(cidfile),
                "--label", "tomorrowci.control-run=" + run_key, "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=1000:1000",
                "--memory=768m", "--cpus=1", "--pids-limit=128",
                "--tmpfs", "/work:rw,nosuid,nodev,size=384m,mode=1777",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--mount", "type=bind,source=" + str(inputs) + ",target=/inputs,readonly",
                args.image, "python", "-I", "/inputs/container_runner.py", name]
        case = dict(name=name, commands=[], expected_exit=selected["expected_exit"], expected_summary=selected["expected_summary"])
        receipt["controls"].append(case)
        print("START", name, flush=True)
        code, out, err = command(argv, destination, "control", case["commands"])
        if code is None and cidfile.exists():
            cid = cidfile.read_text().strip()
            if re.fullmatch(r"[0-9a-f]{64}", cid):
                inspect_code, inspected, _ = command(["docker", "inspect", cid], destination, "timeout-inspect", case["commands"], 30)
                if inspect_code == 0 and json.loads(inspected)[0]["Config"]["Labels"].get("tomorrowci.control-run") == run_key:
                    command(["docker", "rm", "-f", cid], destination, "timeout-owned-cleanup", case["commands"], 30)
        summaries = [line[len(PREFIX):] for line in (out + "\n" + err).splitlines() if line.startswith(PREFIX)]
        errors = []
        if code != selected["expected_exit"]:
            errors.append("unexpected exit")
        if len(summaries) != 1:
            errors.append("expected one summary")
        else:
            try:
                summary = json.loads(summaries[0])
                case["summary"] = summary
                if summary.get("schema_version") != 1 or summary.get("framework") != "pytest" or summary.get("exit_code") != code:
                    errors.append("invalid summary header/exit")
                for key, value in selected["expected_summary"].items():
                    if summary.get(key) != value:
                        errors.append("unexpected " + key)
                if name != "wrong-source-origin" and summary.get("source_origins") != {"trial_subject": "trial_subject/__init__.py"}:
                    errors.append("wrong source origin")
            except (ValueError, TypeError):
                errors.append("invalid summary JSON")
        case["errors"] = errors
        case["status"] = "PASS" if not errors else "FAIL"
        write_json(work / "summary.json", receipt)
        print("END", name, case["status"], flush=True)
    receipt["finished_at"] = timestamp()
    receipt["status"] = "PASS" if all(item["status"] == "PASS" for item in receipt["controls"]) else "FAIL"
    write_json(work / "summary.json", receipt)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
