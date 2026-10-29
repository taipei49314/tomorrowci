#!/usr/bin/env python3
"""Prepare an isolated, source-pinned Python trial without running target code."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
RESERVED = (".tomorrowci.yml", ".tomorrowci-trial.py", ".tomorrowci-trial-profile.json",
            ".tomorrowci-dependencies.json")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_bytes(path: Path, *args: str) -> bytes:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_CONFIG_") or key in (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
        ):
            env.pop(key)
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1")
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.autocrlf=false",
               "-c", "core.hooksPath=" + str(path / ".git/tomorrowci-no-hooks"), *args]
    result = subprocess.run(command, cwd=path, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("Git operation failed: " + result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def git(path: Path, *args: str) -> str:
    return git_bytes(path, *args).decode("utf-8").strip()


def plan_file_links(source: Path, head: str, enabled: bool) -> dict:
    """Resolve only committed file blobs, without following host filesystem links."""
    entries = {}
    for entry in git_bytes(source, "ls-tree", "-rz", head).split(b"\0"):
        if not entry:
            continue
        header, name = entry.split(b"\t", 1)
        mode, kind, sha = header.decode("ascii").split()
        entries[name.decode("utf-8")] = (mode, kind, sha)
    if any(mode == "160000" for mode, _, _ in entries.values()):
        raise ValueError("Symlinks and submodules: submodules remain unsupported")
    links = {name: sha for name, (mode, _, sha) in entries.items() if mode == "120000"}
    if links and not enabled:
        raise ValueError("Symlinks and submodules are unsupported by default; use --materialize-file-links for internal committed file links")
    result = {}
    for name, link_sha in links.items():
        target = git_bytes(source, "cat-file", "blob", link_sha).decode("utf-8")
        if not target or target.startswith("/") or any(c in target for c in ("\\", ":")) or any(ord(c) < 32 for c in target):
            raise ValueError(f"Unsupported file link target: {name}")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
        if resolved == ".." or resolved.startswith("../"):
            raise ValueError(f"File link escapes checkout: {name}")
        selected = entries.get(resolved)
        if selected is None or selected[0] not in ("100644", "100755") or selected[1] != "blob":
            raise ValueError(f"File link must point directly to a committed regular file: {name}")
        contents = git_bytes(source, "cat-file", "blob", selected[2])
        result[name] = dict(target=target, resolved_path=resolved, link_blob_sha=link_sha,
                            target_blob_sha=selected[2], target_mode=selected[0],
                            materialized_sha256=digest(contents), contents=contents)
    return result


def minor(value: str) -> tuple[int, int]:
    if not re.fullmatch(r"3\.(0|[1-9][0-9]{0,2})", value):
        raise ValueError("Python versions must be canonical minor versions, e.g. 3.12")
    return tuple(map(int, value.split(".")))


def prepare(*, source: Path, output: Path, baseline: str, candidate: str,
            framework: str, source_root: str, packages: list[str],
            test_args: list[str], requirements: Path | None = None,
            stdlib_only: bool = False, timeout: int = 300,
            materialize_file_links: bool = False) -> dict:
    source, output = source.resolve(), output.resolve()
    if output.exists():
        raise ValueError("Output already exists; choose a new directory")
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("Source and output directories must not overlap")
    if minor(candidate) <= minor(baseline):
        raise ValueError("Candidate must be later than baseline")
    if framework not in ("unittest", "pytest"):
        raise ValueError("Framework must be unittest or pytest")
    if not packages or any(not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", p)
                           for p in packages):
        raise ValueError("At least one valid source package is required")
    root = PurePosixPath(source_root)
    if root.is_absolute() or ".." in root.parts or "\\" in source_root or ":" in source_root:
        raise ValueError("Source root must be a checkout-relative POSIX path")
    if not (source / source_root).is_dir():
        raise ValueError("Source root directory does not exist")
    command_parts = ["python", ".tomorrowci-trial.py", "--framework", framework,
                     "--source-root", str(root)]
    for package in packages:
        command_parts.extend(["--source-package", package])
    command_parts.extend(["--", *test_args])
    if not test_args or any(not arg or any(c.isspace() for c in arg) for arg in command_parts):
        raise ValueError("Provide test arguments after --; arguments containing whitespace are unsupported")
    if timeout < 1 or timeout > 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds")
    if stdlib_only and (requirements is not None or framework != "unittest"):
        raise ValueError("stdlib-only requires unittest and no requirements argument")
    if git(source, "rev-parse", "--show-prefix"):
        raise ValueError("Source must be the Git checkout root; use --source-root to select a package directory")
    head = git(source, "rev-parse", "HEAD")
    file_links = plan_file_links(source, head, materialize_file_links)
    if git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Source checkout must be clean, including untracked files")
    if any((source / name).exists() for name in RESERVED):
        raise ValueError("Source already contains a TomorrowCI configuration or trial overlay")
    if stdlib_only:
        req_bytes = b"# Explicit standard-library-only trial; no pip dependencies.\n"
        req_origin = "EXPLICIT_STDLIB_ONLY"
    else:
        req_path = (requirements or source / "requirements.txt").resolve()
        if not req_path.is_file():
            raise ValueError("Provide --requirements with project and test dependencies, or explicit --stdlib-only")
        relative_req = req_path.relative_to(source).as_posix() if req_path.is_relative_to(source) else None
        req_bytes = file_links[relative_req]["contents"] if relative_req in file_links else req_path.read_bytes()
        req_bytes.decode("utf-8")
        req_origin = str(req_path)
    wrapper_bytes = (HERE / "python_trial_runner.py").read_bytes()
    config = {
        "version": 1,
        "project": {"ecosystem": "python", "test_command": " ".join(command_parts)},
        "baseline": {"runtime": baseline, "dependencies": "locked"},
        "candidates": {"runtime": {"channels": ["stable"], "versions": [candidate], "max_versions": 1},
                       "dependencies": {"latest_allowed": False, "prerelease": False}},
        "execution": {"max_scenarios": 2, "timeout_seconds": timeout,
                      "reruns_on_failure": 3, "max_parallel": 1},
        "sandbox": {"engine": "docker", "network": "fetch-only", "memory_mb": 2048,
                    "cpus": 1, "pids_limit": 256},
        "report": {"html": True, "json": True},
    }
    # All validation above is read-only. A failed clone stays available for diagnosis.
    output.mkdir(parents=True, exist_ok=False)
    git(source, "clone", "--no-local", "--no-checkout", "--template=", "--", str(source), str(output))
    git(output, "checkout", "--detach", head)
    if git(output, "rev-parse", "HEAD") != head or git(output, "status", "--porcelain=v1"):
        raise ValueError("Cloned source did not match the selected clean commit")
    if not (output / source_root).is_dir():
        raise ValueError("Source root is not present in the committed snapshot")
    if git(source, "rev-parse", "HEAD") != head or git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Original source changed during preparation")
    for name, link in file_links.items():
        destination = output.joinpath(*PurePosixPath(name).parts)
        if not destination.parent.resolve().is_relative_to(output):
            raise ValueError(f"File link destination escapes output: {name}")
        if destination.is_symlink():
            destination.unlink()
        destination.write_bytes(link["contents"])
        destination.chmod(0o755 if link["target_mode"] == "100755" else 0o644)
    (output / ".tomorrowci.yml").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (output / ".tomorrowci-trial.py").write_bytes(wrapper_bytes)
    (output / "requirements.txt").write_bytes(req_bytes)
    result = {
        "schema_version": 1, "status": "PREPARED_NOT_EXECUTED",
        "source": str(source), "source_sha": head, "output": str(output),
        "framework": framework, "source_root": str(root), "source_packages": packages,
        "baseline": baseline, "candidate": candidate, "test_args": test_args,
        "preparer_sha256": digest(Path(__file__).read_bytes()),
        "requirements_origin": req_origin, "requirements_sha256": digest(req_bytes),
        "wrapper_sha256": digest(wrapper_bytes),
        "config_sha256": digest((output / ".tomorrowci.yml").read_bytes()),
        "dependencies_resolved": False, "target_code_executed": False,
        "source_materialization": "committed_file_links_expanded_v1" if file_links else "git_checkout",
        "materialized_file_links": {name: {**{key: value for key, value in link.items() if key != "contents"},
                                          "final_sha256": digest((output / name).read_bytes())}
                                    for name, link in file_links.items()},
        "symlink_identity_preserved": not bool(file_links),
        "next_command": {"cwd": str(output), "argv": ["tomorrowci", "scan", ".", "--config", ".tomorrowci.yml"]},
    }
    (output / ".tomorrowci-trial-profile.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog="Pass the project's existing test arguments after --.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--framework", choices=["unittest", "pytest"], required=True)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--source-package", action="append", required=True, dest="packages")
    deps = parser.add_mutually_exclusive_group()
    deps.add_argument("--requirements", type=Path)
    deps.add_argument("--stdlib-only", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--materialize-file-links", action="store_true",
                        help="Expand internal links to committed regular-file bytes and record the transformation; link identity is not preserved")
    split = argv.index("--") if "--" in argv else len(argv)
    args = vars(parser.parse_args(argv[:split]))
    args["test_args"] = argv[split + 1:]
    try:
        print(json.dumps(prepare(**args), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print("prepare-python-trial: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
