#!/usr/bin/env python3
"""Fail-closed helpers for building and promoting TomorrowCI release candidates."""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urljoin


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
GITHUB_REPOSITORY_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)$"
)
GITHUB_RUN_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)/actions/runs/(?P<run_id>[1-9][0-9]*)$"
)
GITHUB_EVIDENCE_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)/actions/runs/(?P<run_id>[1-9][0-9]*)/artifacts/(?P<artifact_id>[1-9][0-9]*)$"
)
GITHUB_RELEASE_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)/releases/tag/(?P<tag>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
GITHUB_RELEASE_ASSET_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)/releases/download/(?P<tag>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/(?P<asset>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
GITHUB_IDENTITY_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))$"
)
GITHUB_SIGNER_WORKFLOW_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9_.-]+)/"
    r"(?P<path>\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml)$"
)
OCI_IMAGE_DIGEST_RE = re.compile(
    r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9][A-Za-z0-9._-]{0,127})?"
    r"@sha256:[0-9a-f]{64}$"
)
ENGINE_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?$")
ARTIFACT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

CANDIDATE_KIND = "tomorrowci-release-candidate"
PROMOTION_KIND = "tomorrowci-tag-promotion"
ARTIFACT_NAME = "tomorrowci-release-candidate"
QUALIFICATION_ARTIFACT_NAME = "tomorrowci-release-qualification"
CHECKSUMS_NAME = "SHA256SUMS.txt"
MANIFEST_NAME = "candidate-manifest.json"
ATTESTATION_NAME = "TAG_PROMOTION_ATTESTATION.json"
QUALIFICATION_NAME = "qualification-index.json"
CANDIDATE_RUN_BINDING_NAME = "candidate-run-binding.json"
QUALIFICATION_RUN_BINDING_NAME = "qualification-run-binding.json"
QUALIFICATION_RESULT_NAME = "qualification-result.json"
QUALIFICATION_ATTESTATION_BUNDLE_NAME = "qualification-result.attestation.jsonl"
PROJECT_RESULTS_NAME = "project-operated-results.json"
RUN_BINDING_KIND = "tomorrowci-workflow-dispatch-binding"
PROJECT_EXTERNAL_WORKFLOW = ".github/workflows/external-targets.yml"
SBOM_NAME = "sbom.cdx.json"
CLAIM_SNAPSHOT = "claim-to-evidence.snapshot.md"
SUPPORT_SNAPSHOT = "support-matrix.snapshot.md"
EXTERNAL_SNAPSHOT = "external-evidence-index.snapshot.json"
EXTERNAL_PROTOCOL_SNAPSHOT = "external-protocol.snapshot.md"
EXTERNAL_CONFIG_SNAPSHOTS = {
    "python": "external-python.snapshot.yml",
    "node": "external-node.snapshot.yml",
    "rust": "external-rust.snapshot.yml",
}

TARGET_ARCHIVES = {
    "x86_64-unknown-linux-gnu": ".tar.gz",
    "x86_64-pc-windows-msvc": ".zip",
    "x86_64-apple-darwin": ".tar.gz",
}
DOCUMENTS = ("CHANGELOG.md", "LICENSE", "README.md")
ACCEPTANCE_FIXTURE_IDS = (
    "python-runtime-break",
    "baseline-fail",
    "flaky-project",
    "python-dependency-break",
    "node-dependency-break",
    "rust-msrv-break",
)
MAX_EVIDENCE_ZIP_BYTES = 1024 * 1024 * 1024
MAX_EVIDENCE_ZIP_MEMBERS = 100_000
MAX_EVIDENCE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_LIVE_JSON_BYTES = 16 * 1024 * 1024
MAX_ATTESTATION_BUNDLE_BYTES = 64 * 1024 * 1024


class ReleaseError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReleaseError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_regular_file(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is not a regular file: {path}")
    if path.stat().st_size <= 0:
        fail(f"{label} is empty: {path}")


def copy_frozen_external_inputs(args: argparse.Namespace) -> None:
    """Freeze the configs named by the preregistration, without hard-coded projects."""
    repository_root = Path(args.repository_root).resolve(strict=True)
    index_path = Path(args.index)
    protocol_path = Path(args.protocol)
    output = Path(args.output)
    require_regular_file(index_path, "external evidence index")
    require_regular_file(protocol_path, "external qualification protocol")
    value = load_json_object(index_path, "external evidence index")
    targets = value.get("project_operated_targets")
    if not isinstance(targets, list) or len(targets) != 3:
        fail("external evidence index must pre-register exactly three targets")
    output.mkdir(parents=True, exist_ok=True)
    destinations = [
        output / EXTERNAL_SNAPSHOT,
        output / EXTERNAL_PROTOCOL_SNAPSHOT,
        *(output / name for name in EXTERNAL_CONFIG_SNAPSHOTS.values()),
    ]
    if any(path.exists() for path in destinations):
        fail("refusing to overwrite a frozen external input")
    shutil.copyfile(index_path, output / EXTERNAL_SNAPSHOT)
    shutil.copyfile(protocol_path, output / EXTERNAL_PROTOCOL_SNAPSHOT)
    expected_root = (repository_root / "docs" / "qualification" / "external").resolve(
        strict=True
    )
    seen: set[str] = set()
    for index, target in enumerate(targets):
        label = f"project_operated_targets[{index}]"
        if not isinstance(target, dict):
            fail(f"{label} must be an object")
        ecosystem = require_nonempty_string(target, "ecosystem", label).lower()
        if ecosystem not in EXTERNAL_CONFIG_SNAPSHOTS or ecosystem in seen:
            fail(f"{label} ecosystem is unsupported or duplicated")
        config_path = require_nonempty_string(target, "config_path", label)
        relative = PurePosixPath(config_path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[:3] != ("docs", "qualification", "external")
            or len(relative.parts) != 4
            or not relative.name.endswith(".yml")
            or not SAFE_NAME_RE.fullmatch(relative.name)
        ):
            fail(f"{label}.config_path is not a safe external config path")
        unresolved_source = repository_root / Path(*relative.parts)
        require_regular_file(unresolved_source, f"{label} config")
        source = unresolved_source.resolve(strict=True)
        if source.parent != expected_root:
            fail(f"{label}.config_path escapes the external config directory")
        expected_digest = require_nonempty_string(target, "config_sha256", label)
        if not SHA256_RE.fullmatch(expected_digest) or sha256_file(source) != expected_digest:
            fail(f"{label} config digest does not match the preregistration")
        shutil.copyfile(source, output / EXTERNAL_CONFIG_SNAPSHOTS[ecosystem])
        seen.add(ecosystem)
    if seen != set(EXTERNAL_CONFIG_SNAPSHOTS):
        fail("external preregistration must cover Python, Node, and Rust exactly")
    print(f"PASS frozen_external_inputs={output}")


def validate_safe_name(value: str, label: str) -> None:
    if not SAFE_NAME_RE.fullmatch(value):
        fail(f"invalid {label}: {value!r}")


def validate_version(version: str) -> None:
    if not SEMVER_RE.fullmatch(version):
        fail(f"version must be X.Y.Z without a prefix or suffix: {version!r}")


def archive_name(version: str, target: str) -> str:
    validate_version(version)
    try:
        extension = TARGET_ARCHIVES[target]
    except KeyError as error:
        raise ReleaseError(f"unsupported release target: {target}") from error
    return f"tomorrowci-{version}-{target}{extension}"


def archive_root(version: str, target: str) -> str:
    validate_version(version)
    if target not in TARGET_ARCHIVES:
        fail(f"unsupported release target: {target}")
    return f"tomorrowci-{version}-{target}"


def candidate_payload_names(version: str) -> list[str]:
    archives = [archive_name(version, target) for target in sorted(TARGET_ARCHIVES)]
    return sorted(
        archives
        + [
            SBOM_NAME,
            CLAIM_SNAPSHOT,
            SUPPORT_SNAPSHOT,
            EXTERNAL_SNAPSHOT,
            EXTERNAL_PROTOCOL_SNAPSHOT,
            CANDIDATE_RUN_BINDING_NAME,
            *EXTERNAL_CONFIG_SNAPSHOTS.values(),
        ]
    )


def candidate_file_names(version: str) -> list[str]:
    return sorted(candidate_payload_names(version) + [MANIFEST_NAME])


def release_file_names(version: str) -> list[str]:
    return sorted(
        candidate_file_names(version)
        + [
            QUALIFICATION_NAME,
            QUALIFICATION_RUN_BINDING_NAME,
            ATTESTATION_NAME,
            CHECKSUMS_NAME,
        ]
    )


def ensure_exact_files(directory: Path, expected: Iterable[str]) -> None:
    if not directory.is_dir() or directory.is_symlink():
        fail(f"not a regular directory: {directory}")
    expected_set = set(expected)
    actual: set[str] = set()
    for entry in directory.iterdir():
        if not entry.is_file() or entry.is_symlink():
            fail(f"candidate inventory contains a non-regular file: {entry.name}")
        actual.add(entry.name)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set)
    if missing or extra:
        fail(f"inventory mismatch; missing={missing}, extra={extra}")


def normalized_members(root: str, binary: Path, documents: list[Path]) -> list[tuple[str, Path, int]]:
    validate_safe_name(root, "archive root")
    require_regular_file(binary, "release binary")
    if len(documents) != len(DOCUMENTS):
        fail(f"exactly {len(DOCUMENTS)} release documents are required")
    by_name: dict[str, Path] = {}
    for document in documents:
        require_regular_file(document, "release document")
        if document.name not in DOCUMENTS:
            fail(f"unexpected release document: {document.name}")
        if document.name in by_name:
            fail(f"duplicate release document: {document.name}")
        by_name[document.name] = document
    missing = sorted(set(DOCUMENTS) - set(by_name))
    if missing:
        fail(f"missing release documents: {missing}")
    members = [(f"{root}/{binary.name}", binary, 0o755)]
    members.extend((f"{root}/{name}", by_name[name], 0o644) for name in DOCUMENTS)
    return sorted(members)


def package_tar_gz(output: Path, root: str, members: list[tuple[str, Path, int]]) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                root_info = tarfile.TarInfo(f"{root}/")
                root_info.type = tarfile.DIRTYPE
                root_info.mode = 0o755
                root_info.uid = 0
                root_info.gid = 0
                root_info.uname = "root"
                root_info.gname = "root"
                root_info.mtime = 0
                archive.addfile(root_info)
                for member_name, source, mode in members:
                    info = tarfile.TarInfo(member_name)
                    info.size = source.stat().st_size
                    info.mode = mode
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 0
                    with source.open("rb") as handle:
                        archive.addfile(info, handle)


def package_zip(output: Path, root: str, members: list[tuple[str, Path, int]]) -> None:
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        root_info = zipfile.ZipInfo(f"{root}/", date_time=(1980, 1, 1, 0, 0, 0))
        root_info.create_system = 3
        root_info.external_attr = (stat.S_IFDIR | 0o755) << 16
        archive.writestr(root_info, b"")
        for member_name, source, mode in members:
            info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info._compresslevel = 9
            archive.writestr(info, source.read_bytes())


def package_archive(args: argparse.Namespace) -> None:
    binary = Path(args.binary)
    output = Path(args.output)
    documents = [Path(value) for value in args.document]
    members = normalized_members(args.root, binary, documents)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        fail(f"refusing to overwrite archive: {output}")
    if args.format == "tar.gz":
        package_tar_gz(output, args.root, members)
    elif args.format == "zip":
        package_zip(output, args.root, members)
    else:
        fail(f"unsupported archive format: {args.format}")
    require_regular_file(output, "release archive")
    print(f"{sha256_file(output)}  {output.name}")


def expected_archive_members(root: str, binary_name: str) -> list[str]:
    validate_safe_name(root, "archive root")
    validate_safe_name(binary_name, "binary name")
    return sorted([f"{root}/", f"{root}/{binary_name}"] + [f"{root}/{name}" for name in DOCUMENTS])


def validate_archive_member(name: str, root: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        fail(f"unsafe archive path: {name!r}")
    if not path.parts or path.parts[0] != root:
        fail(f"archive member escapes the versioned root: {name!r}")


def archive_entries(archive_path: Path, archive_format: str) -> list[str]:
    if archive_format == "tar.gz":
        with tarfile.open(archive_path, mode="r:gz") as archive:
            names: list[str] = []
            for member in archive.getmembers():
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    fail(f"unsupported tar member type: {member.name}")
                names.append(member.name if not member.isdir() else member.name.rstrip("/") + "/")
            return sorted(names)
    if archive_format == "zip":
        with zipfile.ZipFile(archive_path) as archive:
            names = []
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    fail(f"symlink is forbidden in zip archive: {info.filename}")
                names.append(info.filename)
            return sorted(names)
    fail(f"unsupported archive format: {archive_format}")
    return []


def verify_archive(args: argparse.Namespace) -> None:
    archive_path = Path(args.archive)
    require_regular_file(archive_path, "release archive")
    expected = expected_archive_members(args.root, args.binary_name)
    actual = archive_entries(archive_path, args.format)
    for name in actual:
        validate_archive_member(name, args.root)
    if actual != expected:
        fail(f"archive inventory mismatch; expected={expected}, actual={actual}")
    print(f"PASS archive={archive_path.name} members={len(actual)} root={args.root}")


def extract_archive(args: argparse.Namespace) -> None:
    archive_path = Path(args.archive)
    destination = Path(args.destination)
    verify_args = argparse.Namespace(
        archive=str(archive_path),
        format=args.format,
        root=args.root,
        binary_name=args.binary_name,
    )
    verify_archive(verify_args)
    if destination.exists() and any(destination.iterdir()):
        fail(f"extraction destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    if args.format == "tar.gz":
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive.getmembers():
                target = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    fail(f"could not read archive member: {member.name}")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, member.mode & 0o777)
    else:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                target = destination.joinpath(*PurePosixPath(info.filename).parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                mode = (info.external_attr >> 16) & 0o777
                if mode:
                    os.chmod(target, mode)


def acceptance_run_inventory(evidence_root: Path) -> tuple[list[str], list[str]]:
    """Bind release smoke tests to the six measured fixtures plus the sealed Patch Lab run."""
    evidence_root = evidence_root.resolve(strict=True)
    report = load_json_object(
        evidence_root / "measure" / "suite-report.json",
        "downloaded acceptance suite report",
    )
    expected_report_fields = {
        "engine_available",
        "engine_detail",
        "engine_requested",
        "finished_at",
        "fixtures",
        "ledger",
        "started_at",
        "tool_version",
        "trustworthy",
    }
    if set(report) != expected_report_fields:
        fail("acceptance suite report has unknown or missing top-level fields")
    if report.get("engine_available") is not True or report.get("trustworthy") is not True:
        fail("acceptance suite report is not trustworthy with an available engine")
    fixtures = report.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != len(ACCEPTANCE_FIXTURE_IDS):
        fail("acceptance suite report must contain exactly six fixture results")

    runs_root = evidence_root / "runs"
    if not runs_root.is_dir() or runs_root.is_symlink():
        fail("downloaded acceptance evidence has no regular runs directory")
    fixture_run_ids: list[str] = []
    fixture_fields = {
        "claims",
        "duration_ms",
        "evidence_dir",
        "id",
        "path",
        "run_id",
        "terminal_summary",
    }
    for index, (fixture, expected_id) in enumerate(zip(fixtures, ACCEPTANCE_FIXTURE_IDS)):
        label = f"acceptance fixtures[{index}]"
        if not isinstance(fixture, dict) or set(fixture) != fixture_fields:
            fail(f"{label} has unknown or missing fields")
        fixture_path = fixture.get("path")
        normalized_fixture_path = (
            fixture_path.replace("\\", "/").rstrip("/")
            if isinstance(fixture_path, str)
            else ""
        )
        expected_fixture_suffix = f"fixtures/{expected_id}"
        if fixture.get("id") != expected_id or not (
            normalized_fixture_path == expected_fixture_suffix
            or normalized_fixture_path.endswith(f"/{expected_fixture_suffix}")
        ):
            fail(f"{label} is not the expected built-in fixture")
        run_id = fixture.get("run_id")
        if not isinstance(run_id, str):
            fail(f"{label} has no sealed run ID")
        validate_safe_name(run_id, f"{label} run ID")
        if run_id in fixture_run_ids:
            fail("acceptance suite report duplicates a fixture run ID")
        evidence_dir = fixture.get("evidence_dir")
        normalized_evidence_dir = (
            evidence_dir.replace("\\", "/").rstrip("/")
            if isinstance(evidence_dir, str)
            else ""
        )
        if not normalized_evidence_dir.endswith(f"/runs/{run_id}"):
            fail(f"{label} evidence directory is not bound to its run ID")
        if (
            isinstance(fixture.get("duration_ms"), bool)
            or not isinstance(fixture.get("duration_ms"), int)
            or fixture["duration_ms"] < 0
            or not isinstance(fixture.get("claims"), list)
            or not fixture["claims"]
            or not isinstance(fixture.get("terminal_summary"), str)
            or not fixture["terminal_summary"].strip()
        ):
            fail(f"{label} has incomplete measurement evidence")
        run_directory = runs_root / run_id
        if not run_directory.is_dir() or run_directory.is_symlink():
            fail(f"{label} run directory is missing")
        run = load_json_object(run_directory / "run.json", f"{label} run identity")
        if run.get("run_id") != run_id:
            fail(f"{label} run.json identity differs from the suite report")
        fixture_run_ids.append(run_id)

    actual_run_ids: list[str] = []
    for entry in runs_root.iterdir():
        if not entry.is_dir() or entry.is_symlink():
            fail(f"acceptance runs inventory contains an unsafe entry: {entry.name}")
        validate_safe_name(entry.name, "acceptance run directory")
        actual_run_ids.append(entry.name)
    if len(actual_run_ids) != len(set(actual_run_ids)):
        fail("acceptance runs inventory contains duplicate run IDs")

    patches_root = evidence_root / "patches"
    if not patches_root.is_dir() or patches_root.is_symlink():
        fail("downloaded acceptance evidence has no regular Patch Lab directory")
    proof_paths = sorted(patches_root.glob("*/patch-proof.json"))
    if len(proof_paths) != 1:
        fail("acceptance evidence must contain exactly one sealed Patch Lab proof")
    proof_path = proof_paths[0]
    require_regular_file(proof_path, "acceptance Patch Lab proof")
    proof = load_json_object(proof_path, "acceptance Patch Lab proof")
    original = proof.get("original")
    patched = proof.get("patched")
    if (
        proof.get("schema_version") != 2
        or proof.get("disposition") != "QUALIFIED"
        or proof.get("original_unchanged") is not True
        or not isinstance(original, dict)
        or not isinstance(patched, dict)
    ):
        fail("acceptance Patch Lab proof is not a qualified schema-v2 proof")
    original_run_id = original.get("run_id")
    patched_run_id = patched.get("run_id")
    if not isinstance(patched_run_id, str):
        fail("acceptance Patch Lab proof has no patched run ID")
    validate_safe_name(patched_run_id, "acceptance patched run ID")
    if original_run_id not in fixture_run_ids or patched_run_id in fixture_run_ids:
        fail("acceptance Patch Lab proof is not bound to one fixture and one distinct patched run")
    expected_run_ids = set(fixture_run_ids) | {patched_run_id}
    if set(actual_run_ids) != expected_run_ids:
        fail("acceptance run directories differ from the suite and Patch Lab proof inventory")
    return fixture_run_ids, sorted(expected_run_ids)


def write_run_id_list(path: Path, values: list[str], label: str) -> None:
    if path.exists():
        fail(f"refusing to overwrite {label}: {path}")
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8", newline="\n")


def acceptance_runs(args: argparse.Namespace) -> None:
    fixture_run_ids, all_run_ids = acceptance_run_inventory(Path(args.evidence_root))
    write_run_id_list(Path(args.fixture_output), fixture_run_ids, "fixture run plan")
    write_run_id_list(Path(args.all_output), all_run_ids, "complete run plan")
    print(
        f"PASS acceptance_fixture_runs={len(fixture_run_ids)} "
        f"all_sealed_runs={len(all_run_ids)}"
    )


def prepare_replay(args: argparse.Namespace) -> None:
    if not GIT_SHA_RE.fullmatch(args.expected_source_sha):
        fail("expected replay producer source SHA is invalid")
    evidence_root = Path(args.evidence_root)
    fixtures_root = Path(args.fixtures_root)
    runs_root = evidence_root / "runs"
    fixture_run_ids, _ = acceptance_run_inventory(evidence_root)
    runs = [runs_root / run_id for run_id in fixture_run_ids]
    selected: tuple[Path, Path, int] | None = None
    fallback: tuple[Path, Path, int] | None = None
    for run_path in runs:
        scenarios_root = run_path / "scenarios"
        if not scenarios_root.is_dir() or scenarios_root.is_symlink():
            fail(f"sealed run has no regular scenarios directory: {run_path.name}")
        scenarios = sorted(
            path for path in scenarios_root.iterdir() if path.is_dir() and not path.is_symlink()
        )
        for scenario_path in scenarios:
            require_regular_file(
                scenario_path / "replay-manifest-v2.json",
                "sealed scenario replay manifest",
            )
            result = load_json_object(scenario_path / "result.json", "sealed scenario result")
            if result.get("scenario_id") != scenario_path.name:
                fail("sealed scenario directory and result identity differ")
            result_exit_code = result.get("exit_code")
            if (
                not isinstance(result_exit_code, bool)
                and isinstance(result_exit_code, int)
                and result.get("timed_out") is False
                and result.get("blocked_reason") is None
            ):
                if fallback is None:
                    fallback = (run_path, scenario_path, result_exit_code)
                if (scenario_path / "replay-qualification.json").is_file():
                    selected = (run_path, scenario_path, result_exit_code)
                    break
        if selected is not None:
            break
    if selected is None:
        selected = fallback
    if selected is None:
        fail("downloaded evidence contains no replayable non-blocked scenario")
    run_path, scenario_path, sealed_exit_code = selected
    run = load_json_object(run_path / "run.json", "sealed run identity")
    if run.get("run_id") != run_path.name:
        fail("sealed run directory and run.json identity differ")
    repository = run.get("repository")
    if not isinstance(repository, dict):
        fail("sealed run repository identity is missing")
    source = repository.get("source")
    if not isinstance(source, str):
        fail("sealed run repository source is missing")
    normalized_source = source.replace("\\", "/").rstrip("/")
    fixture_name = normalized_source.rsplit("/", 1)[-1]
    validate_safe_name(fixture_name, "sealed fixture name")
    if not normalized_source.endswith(f"/fixtures/{fixture_name}"):
        fail("sealed run source is not a project fixture")
    fixture = fixtures_root / fixture_name
    if not fixture.is_dir() or fixture.is_symlink():
        fail(f"checked-out fixture is missing: {fixture_name}")
    source_manifest = load_json_object(run_path / "source-manifest.json", "source manifest")
    if source_manifest.get("schema_version") != 2:
        fail("source manifest must use schema version 2")
    if source_manifest.get("commit_sha") != args.expected_source_sha:
        fail("downloaded replay producer source SHA does not match the candidate")
    if repository.get("commit_sha") != args.expected_source_sha:
        fail("sealed run repository commit does not match the candidate")
    files = source_manifest.get("files")
    if not isinstance(files, list) or not files:
        fail("source manifest contains no producer files")
    seen: set[str] = set()
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            fail(f"source manifest files[{index}] is malformed")
        path_value = record.get("path")
        digest = record.get("sha256")
        size = record.get("size_bytes")
        executable = record.get("executable")
        if not isinstance(path_value, str):
            fail(f"source manifest files[{index}] path is malformed")
        relative = PurePosixPath(path_value)
        if relative.is_absolute() or ".." in relative.parts or "\\" in path_value:
            fail(f"source manifest contains an unsafe fixture path: {path_value!r}")
        if path_value in seen:
            fail(f"source manifest duplicates fixture path: {path_value}")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            fail(f"source manifest digest is malformed: {path_value}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            fail(f"source manifest size is malformed: {path_value}")
        if not isinstance(executable, bool):
            fail(f"source manifest executable flag is malformed: {path_value}")
        source_path = fixture.joinpath(*relative.parts)
        if not source_path.is_file() or source_path.is_symlink():
            fail(f"replay producer fixture file is not regular: {path_value}")
        if source_path.stat().st_size != size or f"sha256:{sha256_file(source_path)}" != digest:
            fail(f"checked-out fixture does not match sealed source manifest: {path_value}")
        seen.add(path_value)
    values = {
        "expected_cli_exit_code": "0" if sealed_exit_code == 0 else "3",
        "run_id": run_path.name,
        "scenario_id": scenario_path.name,
        "sealed_exit_code": str(sealed_exit_code),
        "fixture_name": fixture_name,
        "workspace": str(fixture.resolve()),
    }
    if args.github_output:
        append_github_output(Path(args.github_output), values)
    print(json.dumps(values, sort_keys=True))


def walk_components(components: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(components, list):
        return
    for component in components:
        if not isinstance(component, dict):
            fail("SBOM component must be an object")
        yield component
        yield from walk_components(component.get("components", []))


def validate_sbom_file(sbom_path: Path, lock_path: Path, expected_name: str, expected_version: str) -> None:
    require_regular_file(sbom_path, "SBOM")
    require_regular_file(lock_path, "Cargo.lock")
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"could not parse SBOM or Cargo.lock: {error}") from error
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        fail("SBOM must be CycloneDX 1.5")
    metadata_component = sbom.get("metadata", {}).get("component")
    if not isinstance(metadata_component, dict):
        fail("SBOM metadata.component is missing")
    if metadata_component.get("name") != expected_name or metadata_component.get("version") != expected_version:
        fail("SBOM root component identity does not match the release")
    components = list(walk_components(sbom.get("components")))
    if not components:
        fail("SBOM components are empty")
    sbom_pairs = {
        (str(component.get("name")), str(component.get("version")))
        for component in [metadata_component, *components]
        if component.get("name") is not None and component.get("version") is not None
    }
    lock_packages = lock.get("package")
    if not isinstance(lock_packages, list) or not lock_packages:
        fail("Cargo.lock contains no packages")
    lock_pairs = {(str(package["name"]), str(package["version"])) for package in lock_packages}
    missing = sorted(lock_pairs - sbom_pairs)
    if missing:
        fail(f"SBOM omits locked packages: {missing[:10]}")
    dependencies = sbom.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        fail("SBOM dependency graph is empty")


def validate_sbom(args: argparse.Namespace) -> None:
    validate_version(args.expected_version)
    validate_sbom_file(
        Path(args.sbom), Path(args.lock), args.expected_name, args.expected_version
    )
    print(f"PASS sbom={args.sbom} lock={args.lock}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def nested_component_refs(component: dict[str, Any]) -> Iterable[str]:
    reference = component.get("bom-ref")
    if not isinstance(reference, str) or not reference:
        fail("CycloneDX component is missing a nonempty bom-ref")
    yield reference
    children = component.get("components", [])
    if not isinstance(children, list):
        fail(f"CycloneDX component {reference} has malformed nested components")
    for child in children:
        if not isinstance(child, dict):
            fail(f"CycloneDX component {reference} contains a non-object child")
        yield from nested_component_refs(child)


def source_date_timestamp(epoch: str) -> str:
    if not re.fullmatch(r"0|[1-9][0-9]*", epoch):
        fail("SOURCE_DATE_EPOCH must be a nonnegative base-10 integer")
    value = int(epoch)
    try:
        instant = datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise ReleaseError(f"SOURCE_DATE_EPOCH is out of range: {epoch}") from error
    return instant.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")


def merge_sboms(args: argparse.Namespace) -> None:
    output = Path(args.output)
    if output.exists():
        fail(f"refusing to overwrite merged SBOM: {output}")
    validate_version(args.expected_version)
    expected_timestamp = source_date_timestamp(args.source_date_epoch)
    metadata = load_json_object(Path(args.metadata), "Cargo metadata")
    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(workspace_members, list):
        fail("Cargo metadata must contain packages and workspace_members arrays")
    package_by_id = {
        package.get("id"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }
    if set(package_by_id) != set(workspace_members) or len(package_by_id) != len(workspace_members):
        fail("Cargo metadata must be generated with --no-deps for the exact virtual workspace")
    expected_members: dict[tuple[str, str], dict[str, Any]] = {}
    for member_id in workspace_members:
        package = package_by_id.get(member_id)
        if not isinstance(package, dict):
            fail(f"workspace member is absent from Cargo metadata packages: {member_id}")
        identity = (str(package.get("name")), str(package.get("version")))
        if identity in expected_members:
            fail(f"duplicate workspace member package identity: {identity}")
        expected_members[identity] = package

    input_paths = [Path(value) for value in args.input]
    if len(input_paths) != len(expected_members):
        fail(
            f"expected one member BOM per workspace package ({len(expected_members)}), "
            f"got {len(input_paths)}"
        )
    roots_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    roots_by_ref: dict[str, dict[str, Any]] = {}
    member_boms: list[dict[str, Any]] = []
    tools_identity: str | None = None
    tools: Any = None
    for path in sorted(input_paths, key=lambda item: item.as_posix()):
        bom = load_json_object(path, "workspace member SBOM")
        if (
            bom.get("bomFormat") != "CycloneDX"
            or bom.get("specVersion") != "1.5"
            or bom.get("version") != 1
        ):
            fail(f"workspace member SBOM is not CycloneDX 1.5 version 1: {path}")
        bom_metadata = bom.get("metadata")
        if not isinstance(bom_metadata, dict):
            fail(f"workspace member SBOM metadata is missing: {path}")
        if bom_metadata.get("timestamp") != expected_timestamp:
            fail(f"workspace member SBOM ignored SOURCE_DATE_EPOCH: {path}")
        root = bom_metadata.get("component")
        if not isinstance(root, dict):
            fail(f"workspace member SBOM root component is missing: {path}")
        identity = (str(root.get("name")), str(root.get("version")))
        if identity not in expected_members:
            fail(f"SBOM root is not an exact Cargo workspace member: {identity}")
        if identity in roots_by_identity:
            fail(f"duplicate member SBOM root: {identity}")
        root_reference = root.get("bom-ref")
        if not isinstance(root_reference, str) or not root_reference:
            fail(f"member SBOM root has no bom-ref: {identity}")
        if root_reference in roots_by_ref:
            fail(f"duplicate member SBOM bom-ref: {root_reference}")
        current_tools = bom_metadata.get("tools")
        current_tools_identity = canonical_json(current_tools)
        if tools_identity is None:
            tools_identity = current_tools_identity
            tools = copy.deepcopy(current_tools)
        elif current_tools_identity != tools_identity:
            fail("workspace member SBOMs disagree on generator identity")
        roots_by_identity[identity] = copy.deepcopy(root)
        roots_by_ref[root_reference] = roots_by_identity[identity]
        member_boms.append(bom)
    if set(roots_by_identity) != set(expected_members):
        missing = sorted(set(expected_members) - set(roots_by_identity))
        fail(f"workspace member BOM roots are incomplete: {missing}")

    components_by_ref: dict[str, dict[str, Any]] = dict(roots_by_ref)
    component_identities: dict[str, str] = {
        reference: canonical_json(component)
        for reference, component in components_by_ref.items()
    }
    for bom in member_boms:
        components = bom.get("components")
        if not isinstance(components, list) or not components:
            fail("workspace member SBOM contains no components")
        for component in components:
            if not isinstance(component, dict):
                fail("workspace member SBOM contains a non-object component")
            reference = component.get("bom-ref")
            if not isinstance(reference, str) or not reference:
                fail("workspace member SBOM component has no bom-ref")
            if reference in roots_by_ref:
                continue
            identity = canonical_json(component)
            previous = component_identities.get(reference)
            if previous is not None and previous != identity:
                fail(f"conflicting dependency component for bom-ref: {reference}")
            if previous is None:
                components_by_ref[reference] = copy.deepcopy(component)
                component_identities[reference] = identity

    dependencies_by_ref: dict[str, dict[str, Any]] = {}
    for bom in member_boms:
        dependencies = bom.get("dependencies")
        if not isinstance(dependencies, list) or not dependencies:
            fail("workspace member SBOM dependency graph is empty")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                fail("workspace member SBOM contains a malformed dependency record")
            reference = dependency.get("ref")
            depends_on = dependency.get("dependsOn", [])
            if not isinstance(reference, str) or not isinstance(depends_on, list):
                fail("workspace member SBOM dependency record is malformed")
            normalized = copy.deepcopy(dependency)
            normalized["dependsOn"] = sorted(set(str(value) for value in depends_on))
            previous = dependencies_by_ref.get(reference)
            if previous is not None and canonical_json(previous) != canonical_json(normalized):
                fail(f"conflicting dependency graph entry for bom-ref: {reference}")
            dependencies_by_ref[reference] = normalized

    root_ref = f"pkg:cargo/tomorrowci-workspace@{args.expected_version}"
    if root_ref in components_by_ref or root_ref in dependencies_by_ref:
        fail("synthetic workspace root collides with a member component")
    workspace_root = {
        "type": "application",
        "bom-ref": root_ref,
        "name": "tomorrowci-workspace",
        "version": args.expected_version,
        "scope": "required",
        "purl": root_ref,
    }
    dependencies_by_ref[root_ref] = {
        "ref": root_ref,
        "dependsOn": sorted(roots_by_ref),
    }
    all_component_refs = {root_ref}
    for component in components_by_ref.values():
        all_component_refs.update(nested_component_refs(component))
    for dependency in dependencies_by_ref.values():
        if dependency["ref"] not in all_component_refs:
            fail(f"dependency graph references an absent component: {dependency['ref']}")
        missing_refs = sorted(set(dependency["dependsOn"]) - all_component_refs)
        if missing_refs:
            fail(f"dependency graph has absent dependsOn references: {missing_refs[:5]}")

    merged = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": expected_timestamp,
            "tools": tools,
            "component": workspace_root,
            "properties": [
                {
                    "name": "tomorrowci:release:source-date-epoch",
                    "value": args.source_date_epoch,
                },
                {
                    "name": "tomorrowci:release:workspace-member-count",
                    "value": str(len(expected_members)),
                },
            ],
        },
        "components": sorted(
            components_by_ref.values(), key=lambda component: str(component["bom-ref"])
        ),
        "dependencies": sorted(
            dependencies_by_ref.values(), key=lambda dependency: str(dependency["ref"])
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, merged)
    validate_sbom_file(
        output,
        Path(args.lock),
        "tomorrowci-workspace",
        args.expected_version,
    )
    print(
        f"PASS merged_sbom={output} members={len(expected_members)} "
        f"components={len(components_by_ref)} sha256={sha256_file(output)}"
    )


def collect_external_schema_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and not child.startswith("#"):
                refs.add(child.split("#", 1)[0])
            else:
                refs.update(collect_external_schema_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(collect_external_schema_refs(child))
    return refs


def validate_json_schema(args: argparse.Namespace) -> None:
    try:
        import jsonschema
        from referencing import Registry, Resource
    except ImportError as error:
        raise ReleaseError("the pinned jsonschema/referencing packages are required") from error
    schema_path = Path(args.schema)
    schema = load_json_object(schema_path, "CycloneDX JSON schema")
    instance = load_json_object(Path(args.instance), "CycloneDX SBOM")
    references: dict[str, dict[str, Any]] = {}
    for value in args.reference:
        reference_path = Path(value)
        reference = load_json_object(reference_path, "referenced JSON schema")
        references[reference_path.name] = reference
    required_refs = collect_external_schema_refs(schema)
    if required_refs != set(references):
        fail(
            f"JSON schema reference inventory mismatch; required={sorted(required_refs)}, "
            f"provided={sorted(references)}"
        )
    base_uri = str(schema.get("$id", ""))
    resources: dict[str, Any] = {}
    for name, reference in references.items():
        resources[urljoin(base_uri, name)] = reference
        reference_id = reference.get("$id")
        if isinstance(reference_id, str):
            resources[reference_id] = reference
    registry = Registry().with_resources(
        (uri, Resource.from_contents(reference))
        for uri, reference in sorted(resources.items())
    )
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    errors = sorted(
        validator_class(schema, registry=registry).iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        fail(f"CycloneDX JSON schema validation failed at {location}: {first.message}")
    print(f"PASS json_schema={schema_path.name} instance={args.instance}")


def file_record(path: Path) -> dict[str, Any]:
    require_regular_file(path, "candidate file")
    return {"path": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}


def write_json(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(encoded, encoding="utf-8", newline="\n")


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    require_regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReleaseError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def expected_dispatch_binding_inputs(
    mode: str,
    candidate_run_id: str = "",
    candidate_manifest_sha256: str = "",
    qualification_index_sha256: str = "",
) -> dict[str, Any]:
    if mode not in {"candidate", "qualification"}:
        fail(f"unsupported workflow dispatch binding mode: {mode}")
    if mode == "candidate":
        if candidate_run_id or candidate_manifest_sha256 or qualification_index_sha256:
            fail("candidate dispatch binding must not contain qualification inputs")
    else:
        if not candidate_run_id.isdigit() or int(candidate_run_id) <= 0:
            fail("qualification dispatch binding candidate run ID is invalid")
        if not SHA256_RE.fullmatch(candidate_manifest_sha256):
            fail("qualification dispatch binding candidate manifest digest is invalid")
        if not SHA256_RE.fullmatch(qualification_index_sha256):
            fail("qualification dispatch binding input digest is invalid")
    return {
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "candidate_run_id": candidate_run_id,
        "dry_run": True,
        "mode": mode,
        "qualification_index_sha256": qualification_index_sha256,
    }


def validate_run_binding_file(
    path: Path,
    run_id: str,
    run_attempt: int,
    workflow_ref: str,
    expected_inputs: dict[str, Any],
) -> dict[str, Any]:
    value = load_json_object(path, "workflow dispatch binding")
    if set(value) != {"inputs", "kind", "schema_version", "workflow"}:
        fail("workflow dispatch binding has unknown or missing fields")
    if value.get("schema_version") != 1 or value.get("kind") != RUN_BINDING_KIND:
        fail("workflow dispatch binding schema/kind mismatch")
    workflow = value.get("workflow")
    if not isinstance(workflow, dict) or set(workflow) != {"ref", "run_attempt", "run_id"}:
        fail("workflow dispatch binding workflow identity is malformed")
    expected_workflow = {
        "ref": workflow_ref,
        "run_attempt": run_attempt,
        "run_id": int(run_id),
    }
    if workflow != expected_workflow:
        fail("workflow dispatch binding run identity mismatch")
    if value.get("inputs") != expected_inputs:
        fail("workflow dispatch binding inputs mismatch")
    return value


def create_run_binding(args: argparse.Namespace) -> None:
    if not args.run_id.isdigit() or int(args.run_id) <= 0:
        fail("run binding run ID must be a positive integer")
    if not args.run_attempt.isdigit() or int(args.run_attempt) <= 0:
        fail("run binding run attempt must be a positive integer")
    if not args.workflow_ref.strip():
        fail("run binding workflow ref is empty")
    inputs = expected_dispatch_binding_inputs(
        args.mode,
        args.candidate_run_id,
        args.candidate_manifest_sha256,
        args.qualification_index_sha256,
    )
    output = Path(args.output)
    if output.exists():
        fail(f"refusing to overwrite workflow dispatch binding: {output}")
    write_json(
        output,
        {
            "inputs": inputs,
            "kind": RUN_BINDING_KIND,
            "schema_version": 1,
            "workflow": {
                "ref": args.workflow_ref,
                "run_attempt": int(args.run_attempt),
                "run_id": int(args.run_id),
            },
        },
    )
    print(sha256_file(output))


def validate_qualification_run_binding(
    path: Path,
    repository: str,
    qualification_run_id: str,
    candidate_run_id: str,
    candidate_manifest_sha256: str,
    qualification_index_sha256: str,
) -> None:
    value = load_json_object(path, "qualification workflow dispatch binding")
    workflow = value.get("workflow")
    if not isinstance(workflow, dict):
        fail("qualification workflow dispatch binding has no workflow identity")
    run_attempt = workflow.get("run_attempt")
    workflow_ref = workflow.get("ref")
    if (
        isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt <= 0
        or not isinstance(workflow_ref, str)
        or not workflow_ref.startswith(
            f"{repository}/.github/workflows/release.yml@refs/heads/"
        )
    ):
        fail("qualification workflow dispatch binding identity is invalid")
    validate_run_binding_file(
        path,
        qualification_run_id,
        run_attempt,
        workflow_ref,
        expected_dispatch_binding_inputs(
            "qualification",
            candidate_run_id,
            candidate_manifest_sha256,
            qualification_index_sha256,
        ),
    )


def create_checksums(directory: Path, names: list[str]) -> None:
    lines = [f"{sha256_file(directory / name)}  {name}" for name in sorted(names)]
    (directory / CHECKSUMS_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def parse_checksums(path: Path) -> dict[str, str]:
    require_regular_file(path, "checksum manifest")
    text = path.read_text(encoding="utf-8")
    if not text.endswith("\n") or "\r" in text:
        fail("checksum manifest must use canonical LF lines with a final LF")
    records: dict[str, str] = {}
    previous = ""
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not match:
            fail(f"malformed checksum record: {line!r}")
        digest, name = match.groups()
        if name in records:
            fail(f"duplicate checksum record: {name}")
        if previous and name <= previous:
            fail("checksum records are not strictly sorted")
        previous = name
        records[name] = digest
    if not records:
        fail("checksum manifest is empty")
    return records


FROZEN_INDEX_FIELDS = {
    "blocking_reason",
    "candidate_manifest_sha256",
    "candidate_source_sha",
    "candidate_version",
    "independent_results",
    "project_operated_targets",
    "qualification_requirements",
    "schema_version",
    "status",
}
FROZEN_TARGET_FIELDS = {
    "config_path",
    "config_sha256",
    "ecosystem",
    "evidence_sha256",
    "repository",
    "source_sha",
    "status",
    "workflow_url",
}
QUALIFICATION_INDEX_FIELDS = FROZEN_INDEX_FIELDS | {"candidate_artifact_digest"}
BASE_RESULT_FIELDS = {
    "candidate_artifact_digest",
    "candidate_manifest_sha256",
    "config_sha256",
    "ecosystem",
    "engine",
    "engine_version",
    "evidence_artifact_name",
    "evidence_run_id",
    "evidence_sha256",
    "evidence_url",
    "image_digests",
    "replay_exit_code",
    "replay_expected_target_exit_code",
    "replay_outcome_class",
    "replay_scenario_id",
    "result_sha256",
    "repository",
    "run_attempt",
    "run_url",
    "scan_exit_code",
    "source_sha",
    "status",
    "verify_exit_code",
    "signer_workflow",
    "workflow_source_sha",
}
INDEPENDENT_RESULT_FIELDS = BASE_RESULT_FIELDS | {
    "auditor_identity",
    "release_asset_id",
    "release_id",
    "release_tag",
    "release_url",
}


def github_repository_identity(value: str, label: str) -> tuple[str, str]:
    match = GITHUB_REPOSITORY_RE.fullmatch(value)
    if not match:
        fail(f"{label} must be a canonical https://github.com/owner/repository URL")
    return match.group("owner"), match.group("repo")


def validate_frozen_external_snapshot(
    path: Path,
    expected_version: str,
    project_owner: str,
) -> tuple[dict[str, Any], dict[str, tuple[str, str, str]]]:
    value = load_json_object(path, "frozen external evidence index")
    if set(value) != FROZEN_INDEX_FIELDS:
        fail("frozen external evidence index has unknown or missing top-level fields")
    if value.get("schema_version") != 1 or value.get("status") != "BLOCKED_EXTERNAL":
        fail("candidate external snapshot must be schema 1 BLOCKED_EXTERNAL")
    if value.get("candidate_version") != expected_version:
        fail("candidate external snapshot version mismatch")
    if value.get("candidate_source_sha") is not None or value.get("candidate_manifest_sha256") is not None:
        fail("pre-candidate external snapshot cannot claim circular candidate identities")
    requirements = value.get("qualification_requirements")
    expected_requirement_fields = {
        "ecosystems",
        "independent_results_required",
        "project_operated_public_targets_required",
        "required_flow",
        "required_identity",
    }
    if not isinstance(requirements, dict) or set(requirements) != expected_requirement_fields:
        fail("frozen qualification requirements are malformed")
    if (
        requirements.get("project_operated_public_targets_required") != 3
        or requirements.get("independent_results_required") != 1
        or requirements.get("ecosystems") != ["python", "node", "rust"]
        or requirements.get("required_flow") != "scan -> verify -> replay"
        or not isinstance(requirements.get("required_identity"), list)
        or len(requirements["required_identity"]) < 6
    ):
        fail("frozen qualification requirements do not express the release contract")
    targets = value.get("project_operated_targets")
    if not isinstance(targets, list) or len(targets) != 3:
        fail("frozen external snapshot must pre-register exactly three targets")
    protocol_path = path.parent / EXTERNAL_PROTOCOL_SNAPSHOT
    require_regular_file(protocol_path, "frozen external qualification protocol")
    config_digests: dict[str, str] = {}
    for ecosystem, snapshot_name in EXTERNAL_CONFIG_SNAPSHOTS.items():
        snapshot_path = path.parent / snapshot_name
        require_regular_file(snapshot_path, f"frozen {ecosystem} external config")
        config_digests[ecosystem] = sha256_file(snapshot_path)
    identities: dict[str, tuple[str, str, str]] = {}
    seen_repositories: set[str] = set()
    seen_config_paths: set[str] = set()
    for index, target in enumerate(targets):
        label = f"frozen project_operated_targets[{index}]"
        if not isinstance(target, dict) or set(target) != FROZEN_TARGET_FIELDS:
            fail(f"{label} schema mismatch")
        ecosystem = require_nonempty_string(target, "ecosystem", label).lower()
        if ecosystem not in {"python", "node", "rust"} or ecosystem in identities:
            fail(f"{label} ecosystem must be one unique pre-registered supported ecosystem")
        repository = require_nonempty_string(target, "repository", label)
        owner, _ = github_repository_identity(repository, f"{label}.repository")
        if owner.casefold() == project_owner.casefold():
            fail(f"{label} repository is project-owned")
        if repository.casefold() in seen_repositories:
            fail(f"{label} repository is duplicated")
        source_sha = require_nonempty_string(target, "source_sha", label)
        if not GIT_SHA_RE.fullmatch(source_sha):
            fail(f"{label} source_sha is invalid")
        config_path = require_nonempty_string(target, "config_path", label)
        config_sha256 = require_nonempty_string(target, "config_sha256", label)
        relative = PurePosixPath(config_path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[:3] != ("docs", "qualification", "external")
            or len(relative.parts) != 4
            or not relative.name.endswith(".yml")
            or not SAFE_NAME_RE.fullmatch(relative.name)
            or config_path in seen_config_paths
        ):
            fail(f"{label}.config_path is unsafe or duplicated")
        expected_config_sha256 = config_digests[ecosystem]
        if config_sha256 != expected_config_sha256:
            fail(f"{label} is not bound to the frozen exact config bytes")
        if (
            target.get("status") != "NOT_RUN"
            or target.get("workflow_url") is not None
            or target.get("evidence_sha256") is not None
        ):
            fail(f"{label} must remain an unexecuted pre-registration")
        identities[ecosystem] = (repository, source_sha, config_sha256)
        seen_repositories.add(repository.casefold())
        seen_config_paths.add(config_path)
    if set(identities) != {"python", "node", "rust"}:
        fail("frozen target pre-registration must cover Python, Node, and Rust exactly")
    if value.get("independent_results") != []:
        fail("candidate snapshot cannot contain post-candidate independent results")
    if not isinstance(value.get("blocking_reason"), str) or not value["blocking_reason"].strip():
        fail("BLOCKED_EXTERNAL snapshot requires a nonempty blocking reason")
    return value, identities


def require_nonempty_string(record: dict[str, Any], field: str, label: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must contain a nonempty {field}")
    return value


def validate_qualified_result(
    record: Any,
    label: str,
    expected_manifest_sha256: str,
    expected_candidate_artifact_digest: str,
    project_owner: str,
    project_repository: str,
    expected_project_source_sha: str,
    require_auditor: bool,
    expected_config_sha256: str,
) -> tuple[str, str, str]:
    project_parts = project_repository.split("/")
    if (
        len(project_parts) != 2
        or project_parts[0] != project_owner
        or not all(SAFE_NAME_RE.fullmatch(part) for part in project_parts)
    ):
        fail(f"{label} expected project repository identity is malformed")
    if not GIT_SHA_RE.fullmatch(expected_project_source_sha):
        fail(f"{label} expected project workflow source SHA is malformed")
    if not isinstance(record, dict):
        fail(f"{label} must be an object")
    expected_fields = INDEPENDENT_RESULT_FIELDS if require_auditor else BASE_RESULT_FIELDS
    if set(record) != expected_fields:
        fail(f"{label} has unknown or missing fields")
    if record.get("status") != "PASS":
        fail(f"{label} status must be PASS")
    ecosystem = require_nonempty_string(record, "ecosystem", label).lower()
    if ecosystem not in {"python", "node", "rust"}:
        fail(f"{label} ecosystem is unsupported")
    config_sha256 = require_nonempty_string(record, "config_sha256", label)
    if config_sha256 != expected_config_sha256:
        fail(f"{label} is not bound to the frozen exact execution config")
    repository = require_nonempty_string(record, "repository", label)
    repository_owner, _ = github_repository_identity(repository, f"{label}.repository")
    if repository_owner.casefold() == project_owner.casefold():
        fail(f"{label} repository is project-owned, not external: {repository}")
    source_sha = require_nonempty_string(record, "source_sha", label)
    if not GIT_SHA_RE.fullmatch(source_sha):
        fail(f"{label} source_sha is invalid")
    run_url = require_nonempty_string(record, "run_url", label)
    run_match = GITHUB_RUN_RE.fullmatch(run_url)
    if not run_match:
        fail(f"{label} run_url must be a canonical GitHub Actions run URL")
    run_owner = run_match.group("owner")
    run_repository = run_match.group("repo")
    run_id = run_match.group("run_id")
    evidence_url = require_nonempty_string(record, "evidence_url", label)
    if require_auditor:
        evidence_match = GITHUB_RELEASE_ASSET_RE.fullmatch(evidence_url)
        if not evidence_match:
            fail(f"{label} evidence_url must be a canonical public GitHub Release asset URL")
        if (
            evidence_match.group("owner").casefold() != run_owner.casefold()
            or evidence_match.group("repo").casefold() != run_repository.casefold()
        ):
            fail(f"{label} evidence release asset is not owned by the independent run repository")
    else:
        evidence_match = GITHUB_EVIDENCE_RE.fullmatch(evidence_url)
        if not evidence_match:
            fail(f"{label} evidence_url must be a canonical GitHub Actions artifact URL")
        if (
            evidence_match.group("owner").casefold() != run_owner.casefold()
            or evidence_match.group("repo").casefold() != run_repository.casefold()
            or evidence_match.group("run_id") != run_id
        ):
            fail(f"{label} evidence URL is not bound to its workflow run")
    evidence_sha256 = require_nonempty_string(record, "evidence_sha256", label)
    if not SHA256_RE.fullmatch(evidence_sha256):
        fail(f"{label} evidence_sha256 is invalid")
    result_sha256 = require_nonempty_string(record, "result_sha256", label)
    if not SHA256_RE.fullmatch(result_sha256):
        fail(f"{label} result_sha256 is invalid")
    evidence_artifact_name = require_nonempty_string(record, "evidence_artifact_name", label)
    validate_safe_name(evidence_artifact_name, f"{label}.evidence_artifact_name")
    evidence_run_id = require_nonempty_string(record, "evidence_run_id", label)
    validate_safe_name(evidence_run_id, f"{label}.evidence_run_id")
    run_attempt = record.get("run_attempt")
    if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt <= 0:
        fail(f"{label} run_attempt is invalid")
    workflow_source_sha = require_nonempty_string(record, "workflow_source_sha", label)
    if not GIT_SHA_RE.fullmatch(workflow_source_sha):
        fail(f"{label} workflow_source_sha is invalid")
    signer_workflow = require_nonempty_string(record, "signer_workflow", label)
    signer_match = GITHUB_SIGNER_WORKFLOW_RE.fullmatch(signer_workflow)
    if not signer_match:
        fail(f"{label} signer_workflow is not an exact canonical GitHub workflow")
    if (
        signer_match.group("owner").casefold() != run_owner.casefold()
        or signer_match.group("repo").casefold() != run_repository.casefold()
    ):
        fail(f"{label} signer_workflow is not owned by the declared run repository")
    candidate_digest = require_nonempty_string(record, "candidate_manifest_sha256", label)
    if candidate_digest != expected_manifest_sha256:
        fail(f"{label} is not bound to the qualified candidate manifest")
    candidate_artifact_digest = require_nonempty_string(
        record, "candidate_artifact_digest", label
    )
    if candidate_artifact_digest != expected_candidate_artifact_digest:
        fail(f"{label} is not bound to the candidate artifact digest")
    engine = require_nonempty_string(record, "engine", label)
    if engine not in {"docker", "podman"}:
        fail(f"{label} engine must be exactly docker or podman")
    engine_version = require_nonempty_string(record, "engine_version", label)
    if not ENGINE_VERSION_RE.fullmatch(engine_version):
        fail(f"{label} engine_version is not a canonical numeric version")
    image_digests = record.get("image_digests")
    if (
        not isinstance(image_digests, list)
        or not image_digests
        or image_digests != sorted(set(image_digests))
        or any(not isinstance(value, str) or not OCI_IMAGE_DIGEST_RE.fullmatch(value) for value in image_digests)
    ):
        fail(f"{label} image_digests must be a sorted unique list of canonical name@sha256 digests")
    for field, accepted in (
        ("scan_exit_code", {0, 3}),
        ("verify_exit_code", {0}),
        ("replay_exit_code", {0, 3}),
    ):
        exit_code = record.get(field)
        if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code not in accepted:
            fail(f"{label} {field} violates the qualifying CLI exit contract")
    replay_scenario_id = require_nonempty_string(record, "replay_scenario_id", label)
    validate_safe_name(replay_scenario_id, f"{label}.replay_scenario_id")
    expected_target_exit = record.get("replay_expected_target_exit_code")
    if (
        isinstance(expected_target_exit, bool)
        or not isinstance(expected_target_exit, int)
        or not 0 <= expected_target_exit <= 255
    ):
        fail(f"{label} replay_expected_target_exit_code is invalid")
    replay_outcome = require_nonempty_string(record, "replay_outcome_class", label)
    expected_replay_contract = (
        (0, "PASS_REPRODUCED")
        if expected_target_exit == 0
        else (3, "TARGET_FAILURE_REPRODUCED")
    )
    if (record["replay_exit_code"], replay_outcome) != expected_replay_contract:
        fail(f"{label} replay outcome does not match the sealed target exit contract")
    if require_auditor:
        auditor = require_nonempty_string(record, "auditor_identity", label)
        auditor_match = GITHUB_IDENTITY_RE.fullmatch(auditor)
        if not auditor_match:
            fail(f"{label} auditor_identity must be a canonical GitHub identity URL")
        auditor_owner = auditor_match.group("owner")
        if auditor_owner.casefold() == project_owner.casefold():
            fail(f"{label} auditor identity is project-owned")
        if run_owner.casefold() != auditor_owner.casefold():
            fail(f"{label} independent run is not owned by the declared auditor")
        release_tag = require_nonempty_string(record, "release_tag", label)
        validate_safe_name(release_tag, f"{label}.release_tag")
        release_url = require_nonempty_string(record, "release_url", label)
        release_match = GITHUB_RELEASE_RE.fullmatch(release_url)
        if not release_match:
            fail(f"{label} release_url must be a canonical public GitHub Release URL")
        release_id = record.get("release_id")
        release_asset_id = record.get("release_asset_id")
        if (
            isinstance(release_id, bool)
            or not isinstance(release_id, int)
            or release_id <= 0
            or isinstance(release_asset_id, bool)
            or not isinstance(release_asset_id, int)
            or release_asset_id <= 0
        ):
            fail(f"{label} release and asset IDs must be positive integers")
        if (
            release_match.group("owner").casefold() != run_owner.casefold()
            or release_match.group("repo").casefold() != run_repository.casefold()
            or release_match.group("tag") != release_tag
            or evidence_match.group("tag") != release_tag
            or evidence_match.group("asset") != evidence_artifact_name
        ):
            fail(f"{label} independent release coordinates are not exactly cross-bound")
    else:
        expected_signer = f"{project_repository}/{PROJECT_EXTERNAL_WORKFLOW}"
        if f"{run_owner}/{run_repository}" != project_repository:
            fail(f"{label} project-operated run must be in {project_repository}")
        if signer_workflow != expected_signer:
            fail(f"{label} project-operated signer must be exactly {expected_signer}")
        if workflow_source_sha != expected_project_source_sha:
            fail(f"{label} project-operated workflow source differs from the candidate source")
    return ecosystem, repository, source_sha


def validate_qualification_index_file(
    path: Path,
    frozen_index_path: Path,
    expected_source_sha: str,
    expected_manifest_sha256: str,
    expected_candidate_artifact_digest: str,
    expected_version: str,
    project_owner: str,
    project_repository: str,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    frozen, registered_targets = validate_frozen_external_snapshot(
        frozen_index_path,
        expected_version,
        project_owner,
    )
    frozen_config_digests = {
        ecosystem: identity[2]
        for ecosystem, identity in registered_targets.items()
    }
    value = load_json_object(path, "qualification index")
    if set(value) != QUALIFICATION_INDEX_FIELDS:
        fail("qualification index has unknown or missing top-level fields")
    if expected_digest is not None:
        if not SHA256_RE.fullmatch(expected_digest) or sha256_file(path) != expected_digest:
            fail("qualification index digest mismatch")
    if value.get("schema_version") != 1 or value.get("status") != "QUALIFIED":
        fail("qualification index must use schema 1 with status QUALIFIED")
    if value.get("candidate_version") != expected_version:
        fail("qualification index candidate version mismatch")
    if value.get("candidate_source_sha") != expected_source_sha:
        fail("qualification index candidate source SHA mismatch")
    if value.get("candidate_manifest_sha256") != expected_manifest_sha256:
        fail("qualification index candidate manifest digest mismatch")
    if (
        not ARTIFACT_DIGEST_RE.fullmatch(expected_candidate_artifact_digest)
        or value.get("candidate_artifact_digest") != expected_candidate_artifact_digest
    ):
        fail("qualification index candidate artifact digest mismatch")
    if value.get("blocking_reason") is not None:
        fail("a QUALIFIED index must set blocking_reason to null")
    if value.get("qualification_requirements") != frozen.get("qualification_requirements"):
        fail("qualification index altered the frozen qualification requirements")
    targets = value.get("project_operated_targets")
    independent = value.get("independent_results")
    if not isinstance(targets, list) or len(targets) != 3:
        fail("qualification index requires exactly the three pre-registered targets")
    if not isinstance(independent, list) or len(independent) < 1:
        fail("qualification index requires at least one independent result")
    target_identities: dict[str, tuple[str, str, str]] = {}
    for index, record in enumerate(targets):
        if not isinstance(record, dict):
            fail(f"project_operated_targets[{index}] must be an object")
        declared_ecosystem = str(record.get("ecosystem", "")).lower()
        expected_config_sha256 = frozen_config_digests.get(declared_ecosystem)
        if expected_config_sha256 is None:
            fail(f"project_operated_targets[{index}] ecosystem is unsupported")
        ecosystem, repository, source_sha = validate_qualified_result(
            record,
            f"project_operated_targets[{index}]",
            expected_manifest_sha256,
            expected_candidate_artifact_digest,
            project_owner,
            project_repository,
            expected_source_sha,
            require_auditor=False,
            expected_config_sha256=expected_config_sha256,
        )
        if ecosystem in target_identities:
            fail(f"qualification index duplicates project-operated ecosystem: {ecosystem}")
        target_identities[ecosystem] = (repository, source_sha, expected_config_sha256)
    if target_identities != registered_targets:
        fail("qualification results do not exactly match the frozen target pre-registration")
    for index, record in enumerate(independent):
        if not isinstance(record, dict):
            fail(f"independent_results[{index}] must be an object")
        ecosystem = str(record.get("ecosystem", "")).lower()
        expected_config_sha256 = frozen_config_digests.get(ecosystem)
        if expected_config_sha256 is None:
            fail(f"independent_results[{index}] ecosystem is unsupported")
        validate_qualified_result(
            record,
            f"independent_results[{index}]",
            expected_manifest_sha256,
            expected_candidate_artifact_digest,
            project_owner,
            project_repository,
            expected_source_sha,
            require_auditor=True,
            expected_config_sha256=expected_config_sha256,
        )
    return value


def validate_qualification(args: argparse.Namespace) -> None:
    validate_qualification_index_file(
        Path(args.index),
        Path(args.frozen_index),
        args.expected_source_sha,
        args.expected_manifest_sha256,
        args.expected_candidate_artifact_digest,
        args.expected_version,
        args.project_owner,
        args.project_repository,
        expected_digest=args.expected_digest,
    )
    print(f"PASS qualification={args.index}")


def export_live_results(args: argparse.Namespace) -> None:
    value = load_json_object(Path(args.index), "qualification index")
    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        fail("live-result export directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    counts = {"project": 0, "independent": 0}
    for kind, field in (
        ("project", "project_operated_targets"),
        ("independent", "independent_results"),
    ):
        records = value.get(field)
        if not isinstance(records, list) or not records:
            fail(f"qualification index has no {field}")
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                fail(f"{field}[{index}] must be an object")
            write_json(output / f"{kind}-{index:02d}.json", record)
            counts[kind] += 1
    print(
        f"PASS live_results={output} project={counts['project']} "
        f"independent={counts['independent']}"
    )


def qualification_attestation_subject(record: dict[str, Any]) -> dict[str, Any]:
    subject = copy.deepcopy(record)
    for field in (
        "evidence_sha256",
        "evidence_url",
        "release_asset_id",
        "release_id",
        "release_url",
        "result_sha256",
    ):
        subject.pop(field, None)
    return subject


EXTERNAL_SELECTION_FIELDS = {
    "config_sha256",
    "ecosystem",
    "engine",
    "engine_version",
    "evidence_run_id",
    "image_digests",
    "replay_expected_cli_exit_code",
    "replay_expected_target_exit_code",
    "replay_outcome_class",
    "replay_scenario_id",
    "repository",
    "scan_exit_code",
    "source_sha",
    "workspace",
}


def external_target_plan(args: argparse.Namespace) -> None:
    """Resolve one target only from the attested, frozen candidate bytes."""
    directory = Path(args.candidate_dir)
    manifest = verify_candidate_directory(
        directory,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_source_sha=args.expected_source_sha,
        expected_run_id=args.expected_run_id,
        expected_version=args.expected_version,
        expected_repository=args.expected_repository,
        lock_path=Path(args.lock) if args.lock else None,
    )
    if not ARTIFACT_DIGEST_RE.fullmatch(args.expected_candidate_artifact_digest):
        fail("candidate artifact digest is not canonical")
    ecosystem = args.ecosystem.lower()
    if ecosystem not in EXTERNAL_CONFIG_SNAPSHOTS:
        fail("external target ecosystem is unsupported")
    _, identities = validate_frozen_external_snapshot(
        directory / EXTERNAL_SNAPSHOT,
        str(manifest["version"]),
        args.project_owner,
    )
    repository, source_sha, config_sha256 = identities[ecosystem]
    config = (directory / EXTERNAL_CONFIG_SNAPSHOTS[ecosystem]).resolve(strict=True)
    if sha256_file(config) != config_sha256:
        fail("resolved external config differs from its frozen digest")
    values = {
        "candidate_source_sha": str(manifest["source_sha"]),
        "candidate_version": str(manifest["version"]),
        "config": str(config),
        "config_sha256": config_sha256,
        "ecosystem": ecosystem,
        "repository": repository,
        "source_sha": source_sha,
    }
    if args.github_output:
        append_github_output(Path(args.github_output), values)
    print(json.dumps(values, sort_keys=True))


def require_inside(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ReleaseError(f"{label} escapes its trusted root") from error


def canonical_image_digest(image_ref: Any, image_digest: Any, label: str) -> str:
    if not isinstance(image_ref, str) or not image_ref or "@" in image_ref:
        fail(f"{label} image_ref must be an unpinned canonical OCI name or tag")
    if not isinstance(image_digest, str) or not ARTIFACT_DIGEST_RE.fullmatch(image_digest):
        fail(f"{label} image_digest is not a canonical sha256 digest")
    value = f"{image_ref}@{image_digest}"
    if not OCI_IMAGE_DIGEST_RE.fullmatch(value):
        fail(f"{label} image identity is not canonical")
    return value


def prepare_external_replay(args: argparse.Namespace) -> None:
    evidence_root = Path(args.evidence_root).resolve(strict=True)
    checkout = Path(args.checkout).resolve(strict=True)
    config = Path(args.config).resolve(strict=True)
    if not SHA256_RE.fullmatch(args.config_sha256) or sha256_file(config) != args.config_sha256:
        fail("external execution config does not match its frozen digest")
    ecosystem = args.ecosystem.lower()
    if ecosystem not in EXTERNAL_CONFIG_SNAPSHOTS:
        fail("external execution ecosystem is unsupported")
    github_repository_identity(args.repository, "external execution repository")
    if not GIT_SHA_RE.fullmatch(args.source_sha):
        fail("external execution source SHA is invalid")
    scan_exit_code = int(args.scan_exit_code)
    if scan_exit_code not in {0, 3}:
        fail("external scan did not produce a qualifying 0/3 outcome")
    runs_root = evidence_root / "runs"
    if not runs_root.is_dir() or runs_root.is_symlink():
        fail("external scan did not create a regular runs directory")
    run_directories = sorted(
        path for path in runs_root.iterdir() if path.is_dir() and not path.is_symlink()
    )
    if len(run_directories) != 1:
        fail("external scan must create exactly one evidence run")
    run_directory = run_directories[0].resolve(strict=True)
    run_id = run_directory.name
    validate_safe_name(run_id, "external evidence run ID")
    run = load_json_object(run_directory / "run.json", "external sealed run")
    repository = run.get("repository")
    detection = run.get("detection")
    if (
        run.get("run_id") != run_id
        or run.get("status") != "COMPLETED"
        or not isinstance(repository, dict)
        or repository.get("commit_sha") != args.source_sha
        or repository.get("is_remote") is not False
        or not isinstance(detection, dict)
        or str(detection.get("ecosystem", "")).lower() != ecosystem
    ):
        fail("external sealed run identity/status differs from the frozen target")
    for field in ("source", "path"):
        value = repository.get(field)
        if not isinstance(value, str) or Path(value).resolve(strict=True) != checkout:
            fail(f"external sealed run repository.{field} differs from the pinned checkout")
    workspace_value = repository.get("workspace_copy")
    if not isinstance(workspace_value, str):
        fail("external sealed run omits workspace_copy")
    workspace = Path(workspace_value).resolve(strict=True)
    expected_workspace_root = (evidence_root / "work" / "workspaces").resolve(strict=True)
    require_inside(workspace, expected_workspace_root, "external replay workspace")
    if workspace.name != run_id or not workspace.is_dir() or workspace.is_symlink():
        fail("external replay workspace is not the run-owned copied source")
    source_manifest = load_json_object(
        run_directory / "source-manifest.json", "external source manifest"
    )
    if (
        source_manifest.get("schema_version") != 2
        or source_manifest.get("commit_sha") != args.source_sha
        or source_manifest.get("dirty") is not False
        or source_manifest.get("identity_kind") != "git_commit"
    ):
        fail("external source manifest is not a clean pinned v2 Git identity")

    frontier = load_json_object(run_directory / "frontier.json", "external frontier")
    observed = frontier.get("observed")
    if not isinstance(observed, bool):
        fail("external frontier observed flag is invalid")
    if observed:
        if scan_exit_code != 3:
            fail("observed external horizon must use scan exit 3")
        scenario_id = frontier.get("scenario_id")
        if not isinstance(scenario_id, str):
            fail("observed external horizon omits its scenario ID")
    else:
        if scan_exit_code != 0 or frontier.get("scenario_id") is not None:
            fail("no-horizon external scan must use exit 0 and no frontier scenario")
        verdicts_path = run_directory / "verdicts.json"
        require_regular_file(verdicts_path, "external verdicts")
        verdicts = json.loads(verdicts_path.read_text(encoding="utf-8"))
        if not isinstance(verdicts, list) or not verdicts:
            fail("external verdicts must be a nonempty array")
        qualifying = [
            item.get("scenario_id")
            for item in verdicts
            if isinstance(item, dict)
            and item.get("verdict") in {"BASELINE_PASS", "FUTURE_PASS"}
            and isinstance(item.get("scenario_id"), str)
        ]
        if not qualifying:
            fail("no-horizon external run has no passing recorded scenario to replay")
        scenario_id = qualifying[-1]
    validate_safe_name(scenario_id, "external replay scenario ID")

    scenarios_root = run_directory / "scenarios"
    if not scenarios_root.is_dir() or scenarios_root.is_symlink():
        fail("external sealed run omits scenarios")
    image_digests: set[str] = set()
    engines: set[tuple[str, str]] = set()
    scenario_directories = sorted(
        path for path in scenarios_root.iterdir() if path.is_dir() and not path.is_symlink()
    )
    if not scenario_directories:
        fail("external sealed run contains no scenario evidence")
    for scenario_directory in scenario_directories:
        manifest = load_json_object(
            scenario_directory / "replay-manifest-v2.json",
            f"external replay manifest {scenario_directory.name}",
        )
        if (
            manifest.get("schema_version") != 2
            or manifest.get("run_id") != run_id
            or manifest.get("scenario_id") != scenario_directory.name
            or not ARTIFACT_DIGEST_RE.fullmatch(str(manifest.get("source_manifest_sha256", "")))
            or not ARTIFACT_DIGEST_RE.fullmatch(str(manifest.get("config_sha256", "")))
        ):
            fail("external run contains an unsealed or cross-bound replay manifest")
        engine = manifest.get("engine")
        if not isinstance(engine, dict):
            fail("external replay manifest omits engine identity")
        engine_name = engine.get("name")
        engine_version = engine.get("server_version")
        if engine_name not in {"docker", "podman"} or not isinstance(engine_version, str):
            fail("external replay engine identity is unsupported")
        if not ENGINE_VERSION_RE.fullmatch(engine_version):
            fail("external replay engine version is not canonical")
        engines.add((engine_name, engine_version))
        image_digests.add(
            canonical_image_digest(
                manifest.get("image_ref"),
                manifest.get("image_digest"),
                f"external replay manifest {scenario_directory.name}",
            )
        )
    if len(engines) != 1:
        fail("external run changed sandbox engine identity across scenarios")

    selected_directory = scenarios_root / scenario_id
    result = load_json_object(selected_directory / "result.json", "external replay result")
    target_exit = result.get("exit_code")
    if (
        result.get("scenario_id") != scenario_id
        or isinstance(target_exit, bool)
        or not isinstance(target_exit, int)
        or not 0 <= target_exit <= 255
        or result.get("signal") is not None
        or result.get("timed_out") is not False
        or result.get("blocked_reason") is not None
    ):
        fail("external replay scenario has no qualifying sealed target result")
    if not observed and target_exit != 0:
        fail("a no-horizon passing replay scenario must have target exit 0")
    if observed and target_exit == 0:
        fail("an observed horizon cannot be backed by a passing target result")
    if observed:
        qualification = load_json_object(
            selected_directory / "replay-qualification.json",
            "external horizon replay qualification",
        )
        attempts = qualification.get("replay_attempts")
        equivalence = qualification.get("replay_equivalence")
        if (
            qualification.get("schema_version") != 2
            or qualification.get("run_id") != run_id
            or qualification.get("scenario_id") != scenario_id
            or qualification.get("equivalent") is not True
            or not isinstance(attempts, list)
            or len(attempts) != 2
            or not isinstance(equivalence, list)
            or len(equivalence) != 2
            or any(
                not isinstance(item, dict)
                or item.get("equivalent") is not True
                or item.get("mismatches") != []
                for item in equivalence
            )
        ):
            fail("observed external horizon lacks two equivalent sealed v2 replays")
    expected_cli_exit = 0 if target_exit == 0 else 3
    engine_name, engine_version = next(iter(engines))
    selection = {
        "config_sha256": args.config_sha256,
        "ecosystem": ecosystem,
        "engine": engine_name,
        "engine_version": engine_version,
        "evidence_run_id": run_id,
        "image_digests": sorted(image_digests),
        "replay_expected_cli_exit_code": expected_cli_exit,
        "replay_expected_target_exit_code": target_exit,
        "replay_outcome_class": (
            "PASS_REPRODUCED" if expected_cli_exit == 0 else "TARGET_FAILURE_REPRODUCED"
        ),
        "replay_scenario_id": scenario_id,
        "repository": args.repository,
        "scan_exit_code": scan_exit_code,
        "source_sha": args.source_sha,
        "workspace": str(workspace),
    }
    output = Path(args.output)
    if output.exists():
        fail("refusing to overwrite external replay selection")
    write_json(output, selection)
    if args.github_output:
        append_github_output(
            Path(args.github_output),
            {
                "expected_cli_exit_code": str(expected_cli_exit),
                "replay_scenario_id": scenario_id,
                "run_id": run_id,
                "workspace": str(workspace),
            },
        )
    print(f"PASS external_replay_selection={ecosystem}/{run_id}/{scenario_id}")


def create_external_subject(args: argparse.Namespace) -> None:
    selection = load_json_object(Path(args.selection), "external replay selection")
    if set(selection) != EXTERNAL_SELECTION_FIELDS:
        fail("external replay selection has unknown or missing fields")
    for field in ("first_replay_exit_code", "second_replay_exit_code"):
        value = int(getattr(args, field))
        if value == 4:
            fail("external replay is BLOCKED (exit 4) and must not emit PASS evidence")
        if value not in {0, 3}:
            fail("external replay has an invalid CLI exit outcome")
        if value != selection["replay_expected_cli_exit_code"]:
            fail("external replay differs from the sealed target exit contract")
    if not SHA256_RE.fullmatch(args.candidate_manifest_sha256):
        fail("external result candidate manifest digest is invalid")
    if not ARTIFACT_DIGEST_RE.fullmatch(args.candidate_artifact_digest):
        fail("external result candidate artifact digest is invalid")
    if not GIT_SHA_RE.fullmatch(args.workflow_source_sha):
        fail("external result workflow source SHA is invalid")
    if not GIT_SHA_RE.fullmatch(args.candidate_source_sha):
        fail("external result candidate source SHA is invalid")
    if args.workflow_source_sha != args.candidate_source_sha:
        fail("project-operated workflow source must equal the candidate source")
    if not args.run_attempt.isdigit() or int(args.run_attempt) <= 0:
        fail("external result workflow run attempt is invalid")
    run_match = GITHUB_RUN_RE.fullmatch(args.run_url)
    signer_match = GITHUB_SIGNER_WORKFLOW_RE.fullmatch(args.signer_workflow)
    if not run_match or not signer_match:
        fail("external result workflow coordinates are not canonical")
    if (
        run_match.group("owner").casefold() != args.project_owner.casefold()
        or signer_match.group("owner").casefold() != run_match.group("owner").casefold()
        or signer_match.group("repo").casefold() != run_match.group("repo").casefold()
    ):
        fail("external result workflow is not project-operated")
    validate_safe_name(args.evidence_artifact_name, "external evidence artifact name")
    subject = {
        "candidate_artifact_digest": args.candidate_artifact_digest,
        "candidate_manifest_sha256": args.candidate_manifest_sha256,
        "config_sha256": selection["config_sha256"],
        "ecosystem": selection["ecosystem"],
        "engine": selection["engine"],
        "engine_version": selection["engine_version"],
        "evidence_artifact_name": args.evidence_artifact_name,
        "evidence_run_id": selection["evidence_run_id"],
        "image_digests": selection["image_digests"],
        "replay_exit_code": selection["replay_expected_cli_exit_code"],
        "replay_expected_target_exit_code": selection[
            "replay_expected_target_exit_code"
        ],
        "replay_outcome_class": selection["replay_outcome_class"],
        "replay_scenario_id": selection["replay_scenario_id"],
        "repository": selection["repository"],
        "run_attempt": int(args.run_attempt),
        "run_url": args.run_url,
        "scan_exit_code": selection["scan_exit_code"],
        "signer_workflow": args.signer_workflow,
        "source_sha": selection["source_sha"],
        "status": "PASS",
        "verify_exit_code": 0,
        "workflow_source_sha": args.workflow_source_sha,
    }
    provisional = copy.deepcopy(subject)
    provisional.update(
        {
            "evidence_sha256": "0" * 64,
            "evidence_url": f"{args.run_url}/artifacts/1",
            "result_sha256": "0" * 64,
        }
    )
    validate_qualified_result(
        provisional,
        "project-operated external subject",
        args.candidate_manifest_sha256,
        args.candidate_artifact_digest,
        args.project_owner,
        args.project_repository,
        args.candidate_source_sha,
        require_auditor=False,
        expected_config_sha256=str(selection["config_sha256"]),
    )
    output = Path(args.output)
    if output.exists():
        fail("refusing to overwrite external attestation subject")
    write_json(output, subject)
    digest = sha256_file(output)
    if args.github_output:
        append_github_output(Path(args.github_output), {"subject_sha256": digest})
    print(f"PASS external_subject={selection['ecosystem']} sha256={digest}")


def stage_external_evidence(args: argparse.Namespace) -> None:
    evidence_root = Path(args.evidence_root).resolve(strict=True)
    selection = load_json_object(Path(args.selection), "external replay selection")
    subject_path = Path(args.subject)
    subject = load_json_object(subject_path, "external attestation subject")
    if set(selection) != EXTERNAL_SELECTION_FIELDS:
        fail("external replay selection has unknown or missing fields")
    if subject != qualification_attestation_subject(subject):
        fail("external evidence subject unexpectedly contains post-upload identity fields")
    if (
        subject.get("evidence_run_id") != selection.get("evidence_run_id")
        or subject.get("replay_scenario_id") != selection.get("replay_scenario_id")
    ):
        fail("external evidence subject differs from the selected sealed run")
    run_id = str(selection["evidence_run_id"])
    source = (evidence_root / "runs" / run_id).resolve(strict=True)
    require_inside(source, (evidence_root / "runs").resolve(strict=True), "external run")
    for entry in source.rglob("*"):
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
            fail("external sealed evidence contains an unsafe filesystem entry")
    output = Path(args.output)
    if output.exists():
        fail("refusing to overwrite staged external evidence")
    output.mkdir(parents=True)
    shutil.copyfile(subject_path, output / QUALIFICATION_RESULT_NAME)
    destination = output / "evidence" / "runs" / run_id
    destination.parent.mkdir(parents=True)
    shutil.copytree(source, destination)
    print(f"PASS staged_external_evidence={run_id}")


def validate_external_evidence_archive(args: argparse.Namespace) -> None:
    selection = load_json_object(Path(args.selection), "external replay selection")
    if set(selection) != EXTERNAL_SELECTION_FIELDS:
        fail("external replay selection has unknown or missing fields")
    subject_path = Path(args.subject)
    require_regular_file(subject_path, "external attestation subject")
    expected_digest = args.expected_digest.removeprefix("sha256:")
    if not SHA256_RE.fullmatch(expected_digest):
        fail("external evidence archive digest is invalid")
    archive_path = Path(args.artifact_zip)
    if sha256_file(archive_path) != expected_digest:
        fail("external evidence archive readback digest mismatch")
    run_id = str(selection["evidence_run_id"])
    scenario_id = str(selection["replay_scenario_id"])
    validate_receipt_rich_evidence_zip(
        archive_path,
        subject_path.read_bytes(),
        run_id,
        scenario_id,
        int(selection["replay_expected_cli_exit_code"]),
        int(selection["replay_expected_target_exit_code"]),
        require_attestation_bundle=False,
    )
    print(f"PASS external_evidence_readback={run_id}/{scenario_id}")


def finalize_external_result(args: argparse.Namespace) -> None:
    subject_path = Path(args.subject)
    subject = load_json_object(subject_path, "external attestation subject")
    expected_subject_fields = BASE_RESULT_FIELDS - {
        "evidence_sha256",
        "evidence_url",
        "result_sha256",
    }
    if set(subject) != expected_subject_fields:
        fail("external attestation subject has unknown or missing fields")
    if not args.artifact_id.isdigit() or int(args.artifact_id) <= 0:
        fail("external evidence artifact ID is invalid")
    if not ARTIFACT_DIGEST_RE.fullmatch(args.artifact_digest):
        fail("external evidence artifact digest is invalid")
    expected_url = f"{subject['run_url']}/artifacts/{args.artifact_id}"
    if args.artifact_url != expected_url:
        fail("external evidence artifact URL is not bound to its workflow run and ID")
    record = copy.deepcopy(subject)
    record.update(
        {
            "evidence_sha256": args.artifact_digest.removeprefix("sha256:"),
            "evidence_url": args.artifact_url,
            "result_sha256": sha256_file(subject_path),
        }
    )
    validate_qualified_result(
        record,
        "project-operated external result",
        str(subject["candidate_manifest_sha256"]),
        str(subject["candidate_artifact_digest"]),
        args.project_owner,
        args.project_repository,
        args.candidate_source_sha,
        require_auditor=False,
        expected_config_sha256=str(subject["config_sha256"]),
    )
    if qualification_attestation_subject(record) != subject:
        fail("final external result changed its pre-upload attestation subject")
    output = Path(args.output)
    if output.exists():
        fail("refusing to overwrite final external result")
    write_json(output, record)
    print(f"PASS finalized_external_result={record['ecosystem']}")


def combine_project_results(args: argparse.Namespace) -> None:
    directory = Path(args.candidate_dir)
    manifest = verify_candidate_directory(
        directory,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_source_sha=args.expected_source_sha,
        expected_run_id=args.expected_run_id,
        expected_version=args.expected_version,
        expected_repository=args.expected_repository,
        lock_path=Path(args.lock) if args.lock else None,
    )
    if not ARTIFACT_DIGEST_RE.fullmatch(args.candidate_artifact_digest):
        fail("combined results candidate artifact digest is invalid")
    _, identities = validate_frozen_external_snapshot(
        directory / EXTERNAL_SNAPSHOT,
        str(manifest["version"]),
        args.project_owner,
    )
    if len(args.result) != 3:
        fail("combined project-operated results require exactly three records")
    records: dict[str, dict[str, Any]] = {}
    for index, path_value in enumerate(args.result):
        record = load_json_object(Path(path_value), f"project-operated result {index}")
        ecosystem = str(record.get("ecosystem", "")).lower()
        expected_identity = identities.get(ecosystem)
        if expected_identity is None or ecosystem in records:
            fail("combined project-operated results have an unsupported or duplicate ecosystem")
        validated = validate_qualified_result(
            record,
            f"project-operated result {ecosystem}",
            args.expected_manifest_sha256,
            args.candidate_artifact_digest,
            args.project_owner,
            args.expected_repository,
            args.expected_source_sha,
            require_auditor=False,
            expected_config_sha256=expected_identity[2],
        )
        if validated != (ecosystem, expected_identity[0], expected_identity[1]):
            fail("combined result differs from its frozen target pre-registration")
        if "independent" in record or "auditor_identity" in record:
            fail("project-operated evidence must never claim independence")
        records[ecosystem] = record
    if set(records) != set(EXTERNAL_CONFIG_SNAPSHOTS):
        fail("combined project-operated results do not cover Python, Node, and Rust")
    output = Path(args.output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        fail("combined project-operated output must be an empty directory")
    output.mkdir(parents=True, exist_ok=True)
    ordered = [records[name] for name in ("python", "node", "rust")]
    for record in ordered:
        target_output = output / str(record["ecosystem"])
        target_output.mkdir()
        write_json(target_output / QUALIFICATION_RESULT_NAME, record)
    aggregate = {
        "candidate_artifact_digest": args.candidate_artifact_digest,
        "candidate_manifest_sha256": args.expected_manifest_sha256,
        "candidate_source_sha": args.expected_source_sha,
        "candidate_version": args.expected_version,
        "kind": "tomorrowci-project-operated-qualification-results",
        "project_operated_targets": ordered,
        "schema_version": 1,
        "status": "QUALIFIED_PROJECT_OPERATED",
    }
    write_json(output / PROJECT_RESULTS_NAME, aggregate)
    digest = sha256_file(output / PROJECT_RESULTS_NAME)
    if args.github_output:
        append_github_output(Path(args.github_output), {"results_sha256": digest})
    print(f"PASS combined_project_results=3 sha256={digest}")


def live_result_coordinates(record: dict[str, Any], kind: str, project_owner: str) -> dict[str, str]:
    if kind not in {"project", "independent"}:
        fail("live result kind must be project or independent")
    run_url = require_nonempty_string(record, "run_url", "live result")
    run_match = GITHUB_RUN_RE.fullmatch(run_url)
    signer = require_nonempty_string(record, "signer_workflow", "live result")
    signer_match = GITHUB_SIGNER_WORKFLOW_RE.fullmatch(signer)
    if not run_match or not signer_match:
        fail("live result has noncanonical GitHub coordinates")
    owner = run_match.group("owner")
    repository = run_match.group("repo")
    if (
        signer_match.group("owner").casefold() != owner.casefold()
        or signer_match.group("repo").casefold() != repository.casefold()
    ):
        fail("live result run and signer workflow repositories differ")
    coordinates = {
        "repository": f"{owner}/{repository}",
        "run_id": run_match.group("run_id"),
        "signer_workflow": signer,
        "workflow_source_sha": require_nonempty_string(
            record, "workflow_source_sha", "live result"
        ),
    }
    if kind == "project":
        if owner.casefold() != project_owner.casefold():
            fail("project-operated live result is not project-owned")
        evidence_url = require_nonempty_string(record, "evidence_url", "live result")
        evidence_match = GITHUB_EVIDENCE_RE.fullmatch(evidence_url)
        if (
            not evidence_match
            or evidence_match.group("owner").casefold() != owner.casefold()
            or evidence_match.group("repo").casefold() != repository.casefold()
            or evidence_match.group("run_id") != run_match.group("run_id")
        ):
            fail("project live result run and Actions artifact coordinates differ")
        coordinates["artifact_id"] = evidence_match.group("artifact_id")
    else:
        auditor = require_nonempty_string(record, "auditor_identity", "live result")
        auditor_match = GITHUB_IDENTITY_RE.fullmatch(auditor)
        if (
            not auditor_match
            or auditor_match.group("owner").casefold() != owner.casefold()
            or owner.casefold() == project_owner.casefold()
        ):
            fail("independent live result is not owned by its nonproject auditor")
        evidence_url = require_nonempty_string(record, "evidence_url", "live result")
        evidence_match = GITHUB_RELEASE_ASSET_RE.fullmatch(evidence_url)
        release_url = require_nonempty_string(record, "release_url", "live result")
        release_match = GITHUB_RELEASE_RE.fullmatch(release_url)
        release_tag = require_nonempty_string(record, "release_tag", "live result")
        release_id = record.get("release_id")
        release_asset_id = record.get("release_asset_id")
        if (
            not evidence_match
            or not release_match
            or evidence_match.group("owner").casefold() != owner.casefold()
            or evidence_match.group("repo").casefold() != repository.casefold()
            or evidence_match.group("tag") != release_tag
            or evidence_match.group("asset") != record.get("evidence_artifact_name")
            or release_match.group("owner").casefold() != owner.casefold()
            or release_match.group("repo").casefold() != repository.casefold()
            or release_match.group("tag") != release_tag
            or isinstance(release_id, bool)
            or not isinstance(release_id, int)
            or release_id <= 0
            or isinstance(release_asset_id, bool)
            or not isinstance(release_asset_id, int)
            or release_asset_id <= 0
        ):
            fail("independent live result release coordinates are malformed or inconsistent")
        coordinates.update(
            {
                "evidence_url": evidence_url,
                "release_asset_id": str(release_asset_id),
                "release_id": str(release_id),
                "release_tag": release_tag,
            }
        )
    return coordinates


def print_live_result_coordinates(args: argparse.Namespace) -> None:
    record = load_json_object(Path(args.record), "live qualification result")
    print(json.dumps(live_result_coordinates(record, args.kind, args.project_owner), sort_keys=True))


def safe_zip_members(path: Path) -> dict[str, zipfile.ZipInfo]:
    require_regular_file(path, "downloaded evidence artifact ZIP")
    if path.stat().st_size > MAX_EVIDENCE_ZIP_BYTES:
        fail("downloaded evidence artifact ZIP exceeds the byte limit")
    members: dict[str, zipfile.ZipInfo] = {}
    casefolded_names: set[str] = set()
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_EVIDENCE_ZIP_MEMBERS:
                fail("evidence artifact ZIP has too many members")
            for info in infos:
                name = info.filename
                relative = PurePosixPath(name)
                canonical_name = relative.as_posix() + ("/" if info.is_dir() else "")
                normalized_name = relative.as_posix().casefold()
                mode = (info.external_attr >> 16) & 0o170000
                total_uncompressed += info.file_size
                if (
                    not name
                    or "\\" in name
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or canonical_name != name
                    or name in members
                    or normalized_name in casefolded_names
                    or info.flag_bits & 0x1
                    or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (info.is_dir() and mode == stat.S_IFREG)
                    or (not info.is_dir() and mode == stat.S_IFDIR)
                    or info.file_size < 0
                    or total_uncompressed > MAX_EVIDENCE_UNCOMPRESSED_BYTES
                ):
                    fail(f"evidence artifact ZIP contains an unsafe member: {name!r}")
                members[name] = info
                casefolded_names.add(normalized_name)
            regular_names = {
                PurePosixPath(name).as_posix().casefold()
                for name, info in members.items()
                if not info.is_dir()
            }
            for name in casefolded_names:
                parts = name.split("/")
                if any("/".join(parts[:index]) in regular_names for index in range(1, len(parts))):
                    fail(f"evidence artifact ZIP has a file/directory path collision: {name!r}")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ReleaseError(f"evidence artifact ZIP is invalid: {error}") from error
    return members


def read_safe_zip_member(
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    name: str,
    byte_limit: int,
) -> bytes:
    info = members.get(name)
    if info is None or info.is_dir():
        fail(f"evidence artifact omits required regular file {name}")
    if info.file_size > byte_limit:
        fail(f"evidence artifact member exceeds its byte limit: {name}")
    try:
        value = archive.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ReleaseError(f"cannot read evidence artifact member {name}: {error}") from error
    if len(value) != info.file_size:
        fail(f"evidence artifact member size changed while reading: {name}")
    return value


def sha256_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info, "r") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                size += len(chunk)
                if size > info.file_size:
                    fail(f"evidence artifact member expanded beyond its declared size: {info.filename}")
                digest.update(chunk)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ReleaseError(f"cannot hash evidence artifact member {info.filename}: {error}") from error
    if size != info.file_size:
        fail(f"evidence artifact member size changed while hashing: {info.filename}")
    return digest.hexdigest()


def validate_zip_inventory(
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    root: str,
    kind: str,
) -> tuple[bytes, dict[str, str]]:
    if not root.endswith("/"):
        fail("internal evidence inventory root is not canonical")
    inventory_name = f"{root}checksums.txt"
    inventory_bytes = read_safe_zip_member(
        archive, members, inventory_name, MAX_LIVE_JSON_BYTES
    )
    try:
        text = inventory_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseError(f"evidence inventory is not UTF-8: {inventory_name}") from error
    expected_header = (
        f"# tomorrowci-evidence-checksums-v2 kind={kind} "
        "algorithm=sha256 scope=recursive sealed=true"
    )
    if not text.endswith("\n") or "\r" in text:
        fail(f"evidence inventory is not canonical LF text: {inventory_name}")
    lines = text.splitlines()
    if not lines or lines[0] != expected_header:
        fail(f"evidence inventory has the wrong sealed-v2 header: {inventory_name}")
    records: dict[str, str] = {}
    previous = ""
    for line in lines[1:]:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"evidence inventory has a malformed record: {inventory_name}")
        digest, relative_name = match.groups()
        relative = PurePosixPath(relative_name)
        if (
            relative.is_absolute()
            or "\\" in relative_name
            or ".." in relative.parts
            or relative.as_posix() != relative_name
            or relative_name == "checksums.txt"
            or not relative.parts
            or relative_name in records
            or (previous and relative_name <= previous)
        ):
            fail(f"evidence inventory path is unsafe, duplicated, or unsorted: {relative_name!r}")
        member_name = f"{root}{relative_name}"
        info = members.get(member_name)
        if info is None or info.is_dir():
            fail(f"evidence inventory lists a missing regular member: {member_name}")
        if sha256_zip_member(archive, info) != digest:
            fail(f"evidence inventory digest mismatch: {member_name}")
        records[relative_name] = digest
        previous = relative_name
    if not records:
        fail(f"evidence inventory is empty: {inventory_name}")
    actual = {
        name.removeprefix(root)
        for name, info in members.items()
        if name.startswith(root) and name != inventory_name and not info.is_dir()
    }
    if set(records) != actual:
        fail(f"evidence inventory does not exactly cover its recursive bundle: {inventory_name}")
    return inventory_bytes, records


def safe_extract_evidence_zip(
    archive_path: Path,
    members: dict[str, zipfile.ZipInfo],
    destination: Path,
) -> None:
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
            fail(f"evidence extraction destination is not a new empty directory: {destination}")
    else:
        destination.mkdir(parents=True)
    with zipfile.ZipFile(archive_path, "r") as archive:
        for name in sorted(members):
            info = members[name]
            if info.is_dir():
                continue
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with archive.open(info, "r") as source, target.open("xb") as output:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        written += len(chunk)
                        if written > info.file_size:
                            fail(f"evidence member expanded beyond its declared size: {name}")
                        output.write(chunk)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise ReleaseError(f"cannot safely extract evidence member {name}: {error}") from error
            if written != info.file_size:
                fail(f"evidence member size changed during extraction: {name}")
            os.chmod(target, 0o600)


def validate_receipt_rich_evidence_zip(
    archive_path: Path,
    expected_subject_bytes: bytes,
    run_id: str,
    scenario_id: str,
    expected_cli_exit: int,
    expected_target_exit: int,
    require_attestation_bundle: bool,
) -> tuple[dict[str, zipfile.ZipInfo], bytes, bytes | None, list[str]]:
    validate_safe_name(run_id, "external archive run ID")
    validate_safe_name(scenario_id, "external archive scenario ID")
    members = safe_zip_members(archive_path)
    run_root = f"evidence/runs/{run_id}/"
    scenario_root = f"{run_root}scenarios/{scenario_id}/"
    scenario_name = f"{scenario_root}result.json"
    receipt_prefix = f"evidence/replay-receipts/{run_id}/{scenario_id}/"
    raw_names = {
        "raw/replay-1.log",
        "raw/replay-2.log",
        "raw/replay-pair.log",
        "raw/replay-1.exit-code",
        "raw/replay-2.exit-code",
    }
    required = {
        QUALIFICATION_RESULT_NAME,
        f"{run_root}checksums.txt",
        f"{scenario_root}checksums.txt",
        scenario_name,
        *raw_names,
    }
    if require_attestation_bundle:
        required.add(QUALIFICATION_ATTESTATION_BUNDLE_NAME)
    missing = sorted(name for name in required if name not in members or members[name].is_dir())
    if missing:
        fail(f"external evidence archive omits required raw package members: {missing}")
    receipt_names = sorted(
        name
        for name, info in members.items()
        if not info.is_dir()
        and name.startswith(receipt_prefix)
        and name.endswith("/public-replay-receipt.json")
    )
    if len(receipt_names) != 2:
        fail("external evidence archive must contain exactly two public replay receipts")
    receipt_roots = [name.removesuffix("public-replay-receipt.json") for name in receipt_names]
    for root in receipt_roots:
        receipt_id = PurePosixPath(root.rstrip("/")).name
        validate_safe_name(receipt_id, "external archive receipt ID")
        if root != f"{receipt_prefix}{receipt_id}/":
            fail("external public replay receipt is not at its canonical run/scenario path")

    allowed_exact = {QUALIFICATION_RESULT_NAME, *raw_names}
    if require_attestation_bundle:
        allowed_exact.add(QUALIFICATION_ATTESTATION_BUNDLE_NAME)
    for name, info in members.items():
        if info.is_dir():
            continue
        if (
            name not in allowed_exact
            and not name.startswith(run_root)
            and not any(name.startswith(root) for root in receipt_roots)
        ):
            fail(f"external evidence archive contains an out-of-contract file: {name}")

    with zipfile.ZipFile(archive_path, "r") as archive:
        run_inventory_bytes, _ = validate_zip_inventory(archive, members, run_root, "run")
        scenario_inventory_bytes, _ = validate_zip_inventory(
            archive, members, scenario_root, "scenario"
        )
        subject_bytes = read_safe_zip_member(
            archive, members, QUALIFICATION_RESULT_NAME, MAX_LIVE_JSON_BYTES
        )
        if subject_bytes != expected_subject_bytes:
            fail("external evidence archive changed its attestation subject bytes")
        scenario_bytes = read_safe_zip_member(
            archive, members, scenario_name, MAX_LIVE_JSON_BYTES
        )
        try:
            scenario = json.loads(scenario_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseError(f"external evidence archive has invalid scenario JSON: {error}") from error
        if (
            not isinstance(scenario, dict)
            or scenario.get("scenario_id") != scenario_id
            or scenario.get("exit_code") != expected_target_exit
            or scenario.get("signal") is not None
            or scenario.get("timed_out") is not False
            or scenario.get("blocked_reason") is not None
        ):
            fail("external evidence archive replay result differs from the sealed contract")

        logged_receipts: dict[str, dict[str, Any]] = {}
        expected_exit_bytes = f"{expected_cli_exit}\n".encode()
        for ordinal in (1, 2):
            exit_bytes = read_safe_zip_member(
                archive,
                members,
                f"raw/replay-{ordinal}.exit-code",
                32,
            )
            if exit_bytes != expected_exit_bytes:
                fail("external replay exit record differs from the sealed contract")
            log_bytes = read_safe_zip_member(
                archive,
                members,
                f"raw/replay-{ordinal}.log",
                MAX_ATTESTATION_BUNDLE_BYTES,
            )
            try:
                log = log_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ReleaseError("external replay log is not UTF-8") from error
            lines = [line for line in log.splitlines() if line.startswith("REPLAY_RECEIPT ")]
            if len(lines) != 1:
                fail("external replay log must contain exactly one receipt record")
            try:
                logged = json.loads(lines[0].removeprefix("REPLAY_RECEIPT "))
            except json.JSONDecodeError as error:
                raise ReleaseError(f"external replay receipt log is invalid JSON: {error}") from error
            receipt_id = str(logged.get("receipt_id", "")) if isinstance(logged, dict) else ""
            path_value = str(logged.get("path", "")) if isinstance(logged, dict) else ""
            expected_suffix = f"/replay-receipts/{run_id}/{scenario_id}/{receipt_id}"
            if (
                not isinstance(logged, dict)
                or set(logged)
                != {
                    "equivalent_to_original",
                    "inventory_sha256",
                    "ordinal",
                    "path",
                    "receipt_id",
                }
                or logged.get("ordinal") != ordinal
                or logged.get("equivalent_to_original") is not True
                or not ARTIFACT_DIGEST_RE.fullmatch(str(logged.get("inventory_sha256", "")))
                or not SAFE_NAME_RE.fullmatch(receipt_id)
                or not path_value.replace("\\", "/").rstrip("/").endswith(expected_suffix)
                or receipt_id in logged_receipts
            ):
                fail("external replay receipt log record is malformed or cross-bound")
            logged_receipts[receipt_id] = logged

        run_inventory_digest = sha256_bytes(run_inventory_bytes)
        scenario_inventory_digest = sha256_bytes(scenario_inventory_bytes)
        receipt_inventory_digests: dict[str, str] = {}
        original_attempt_roots: set[str] = set()
        original_attempt_digests: set[str] = set()
        for receipt_name, receipt_root in zip(receipt_names, receipt_roots, strict=True):
            inventory_bytes, _ = validate_zip_inventory(
                archive, members, receipt_root, "replay-attempt"
            )
            receipt_bytes = read_safe_zip_member(
                archive, members, receipt_name, MAX_LIVE_JSON_BYTES
            )
            try:
                receipt = json.loads(receipt_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ReleaseError(f"external public replay receipt is invalid JSON: {error}") from error
            receipt_id = str(receipt.get("receipt_id", "")) if isinstance(receipt, dict) else ""
            original_attempt_path = (
                str(receipt.get("original_attempt_path", "")) if isinstance(receipt, dict) else ""
            )
            original_attempt = PurePosixPath(original_attempt_path)
            if (
                not isinstance(receipt, dict)
                or receipt.get("schema_version") != 1
                or receipt.get("run_id") != run_id
                or receipt.get("scenario_id") != scenario_id
                or receipt.get("equivalent_to_original") is not True
                or receipt.get("mismatches") != []
                or not SAFE_NAME_RE.fullmatch(receipt_id)
                or receipt_root != f"{receipt_prefix}{receipt_id}/"
                or receipt.get("original_run_inventory_sha256") != run_inventory_digest
                or receipt.get("original_scenario_inventory_sha256")
                != scenario_inventory_digest
                or not ARTIFACT_DIGEST_RE.fullmatch(
                    str(receipt.get("original_attempt_sha256", ""))
                )
                or original_attempt.is_absolute()
                or ".." in original_attempt.parts
                or original_attempt.as_posix() != original_attempt_path
                or len(original_attempt.parts) != 4
                or original_attempt.parts[:3] != ("scenarios", scenario_id, "attempts")
                or not SAFE_NAME_RE.fullmatch(original_attempt.parts[3])
            ):
                fail("external public replay receipt metadata is malformed or cross-bound")
            original_attempt_digests.add(str(receipt["original_attempt_sha256"]))
            original_attempt_root = f"{run_root}{original_attempt_path}/"
            attempt_inventory_bytes, _ = validate_zip_inventory(
                archive, members, original_attempt_root, "replay-attempt"
            )
            if receipt.get("original_attempt_inventory_sha256") != sha256_bytes(
                attempt_inventory_bytes
            ):
                fail("external receipt original attempt inventory digest mismatch")
            original_attempt_roots.add(original_attempt_root)
            origin_bindings = {
                "origin/run.checksums.txt": f"{run_root}checksums.txt",
                "origin/scenario.checksums.txt": f"{scenario_root}checksums.txt",
                "origin/original-attempt.checksums.txt": f"{original_attempt_root}checksums.txt",
                "origin/source-manifest.json": f"{run_root}source-manifest.json",
                "origin/config.normalized.json": f"{run_root}config.normalized.json",
                "origin/scenario.json": f"{scenario_root}scenario.json",
                "origin/replay-manifest-v2.json": f"{scenario_root}replay-manifest-v2.json",
                "origin/original-attempt.json": f"{original_attempt_root}attempt.json",
            }
            for origin_relative, original_name in origin_bindings.items():
                origin_name = f"{receipt_root}{origin_relative}"
                origin_bytes = read_safe_zip_member(
                    archive, members, origin_name, MAX_LIVE_JSON_BYTES
                )
                original_bytes = read_safe_zip_member(
                    archive, members, original_name, MAX_LIVE_JSON_BYTES
                )
                if origin_bytes != original_bytes:
                    fail(f"external receipt origin witness differs from original: {origin_relative}")
            inventory_digest = sha256_bytes(inventory_bytes)
            receipt_inventory_digests[receipt_id] = inventory_digest
            logged = logged_receipts.get(receipt_id)
            if (
                logged is None
                or logged.get("inventory_sha256") != f"sha256:{inventory_digest}"
            ):
                fail("external replay log receipt digest differs from sealed receipt bytes")
        if set(logged_receipts) != set(receipt_inventory_digests):
            fail("external replay logs and sealed receipt identities differ")
        if len(original_attempt_roots) != 1 or len(original_attempt_digests) != 1:
            fail("external replay receipts do not bind the same original attempt")

        pair_bytes = read_safe_zip_member(
            archive, members, "raw/replay-pair.log", MAX_LIVE_JSON_BYTES
        )
        try:
            pair_log = pair_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReleaseError("external replay pair log is not UTF-8") from error
        pair_line = pair_log.removesuffix("\n")
        pair_match = re.fullmatch(
            r"PASS kind=replay-pair receipt_count=2 "
            r"run_id=(?P<run>[A-Za-z0-9._-]+) scenario_id=(?P<scenario>[A-Za-z0-9._-]+) "
            r"original_attempt_sha256=(?P<original>sha256:[0-9a-f]{64}) "
            r"outcome=(?P<outcome>[A-Za-z]+) "
            r"target_exit=Some\((?P<target>[0-9]+)\) "
            r"receipt_ids=(?P<ids>\[[^\r\n ]+\]) "
            r"receipt_inventory_sha256=(?P<digests>\[[^\r\n ]+\])",
            pair_line,
        )
        if not pair_match:
            fail("external replay pair qualification log is malformed or not PASS")
        try:
            pair_ids = json.loads(pair_match.group("ids"))
            pair_digests = json.loads(pair_match.group("digests"))
        except json.JSONDecodeError as error:
            raise ReleaseError(f"external replay pair binding is invalid JSON: {error}") from error
        if (
            pair_match.group("run") != run_id
            or pair_match.group("scenario") != scenario_id
            or pair_match.group("original") not in original_attempt_digests
            or pair_match.group("outcome")
            != ("Passed" if expected_target_exit == 0 else "Failed")
            or int(pair_match.group("target")) != expected_target_exit
            or not isinstance(pair_ids, list)
            or not isinstance(pair_digests, list)
            or len(pair_ids) != 2
            or len(pair_digests) != 2
            or any(not isinstance(value, str) for value in pair_ids + pair_digests)
            or len(set(pair_ids)) != 2
            or {
                receipt_id: digest
                for receipt_id, digest in zip(pair_ids, pair_digests, strict=True)
            }
            != receipt_inventory_digests
        ):
            fail("external replay pair log is not bound to the two sealed receipts")

        bundle_bytes = (
            read_safe_zip_member(
                archive,
                members,
                QUALIFICATION_ATTESTATION_BUNDLE_NAME,
                MAX_ATTESTATION_BUNDLE_BYTES,
            )
            if require_attestation_bundle
            else None
        )
        if require_attestation_bundle and not bundle_bytes:
            fail("independent evidence attestation bundle is empty")
    return members, subject_bytes, bundle_bytes, receipt_roots


def validate_live_result(args: argparse.Namespace) -> None:
    record = load_json_object(Path(args.record), "live qualification result")
    coordinates = live_result_coordinates(record, args.kind, args.project_owner)
    if args.kind == "project":
        expected_signer = f"{args.project_repository}/{PROJECT_EXTERNAL_WORKFLOW}"
        if (
            coordinates["repository"] != args.project_repository
            or coordinates["signer_workflow"] != expected_signer
            or coordinates["workflow_source_sha"] != args.candidate_source_sha
            or not GIT_SHA_RE.fullmatch(args.candidate_source_sha)
            or not isinstance(args.project_default_branch, str)
            or not args.project_default_branch.strip()
        ):
            fail("project-operated live result is not bound to the candidate external workflow")
    repository = load_json_object(Path(args.repository_json), "GitHub repository response")
    if (
        repository.get("full_name") != coordinates["repository"]
        or repository.get("private") is not False
        or repository.get("html_url") != f"https://github.com/{coordinates['repository']}"
    ):
        fail("live result repository is not the declared public GitHub repository")
    run = load_json_object(Path(args.run_json), "GitHub workflow run response")
    signer_path = coordinates["signer_workflow"].split("/", 2)[2]
    run_path = run.get("path")
    expected_run = {
        "id": int(coordinates["run_id"]),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": record["workflow_source_sha"],
        "run_attempt": record["run_attempt"],
        "html_url": record["run_url"],
    }
    if args.kind == "project":
        expected_run["head_branch"] = args.project_default_branch
    for field, expected in expected_run.items():
        if run.get(field) != expected:
            fail(f"live result workflow run {field} mismatch")
    if not isinstance(run_path, str) or run_path.split("@", 1)[0] != signer_path:
        fail("live result workflow run path differs from the declared signer workflow")
    run_repository = run.get("repository")
    if not isinstance(run_repository, dict) or run_repository.get("full_name") != coordinates[
        "repository"
    ]:
        fail("live result workflow run repository mismatch")

    archive_path = Path(args.artifact_zip)
    if sha256_file(archive_path) != record["evidence_sha256"]:
        fail("downloaded raw evidence artifact ZIP digest mismatch")
    if args.kind == "project":
        artifacts_json = getattr(args, "artifacts_json", None)
        if not artifacts_json:
            fail("project live validation requires GitHub Actions artifact metadata")
        artifacts = load_json_object(Path(artifacts_json), "GitHub artifacts response")
        selected = [
            artifact
            for artifact in artifacts.get("artifacts", [])
            if isinstance(artifact, dict) and artifact.get("id") == int(coordinates["artifact_id"])
        ]
        if len(selected) != 1:
            fail("live result evidence artifact ID is absent or duplicated")
        artifact = selected[0]
        if (
            artifact.get("name") != record["evidence_artifact_name"]
            or artifact.get("expired") is not False
            or isinstance(artifact.get("size_in_bytes"), bool)
            or not isinstance(artifact.get("size_in_bytes"), int)
            or artifact["size_in_bytes"] <= 0
            or artifact.get("digest") != f"sha256:{record['evidence_sha256']}"
        ):
            fail("live result server artifact metadata mismatch")
        artifact_run = artifact.get("workflow_run")
        if not isinstance(artifact_run, dict) or (
            artifact_run.get("id") != int(coordinates["run_id"])
            or artifact_run.get("head_sha") != record["workflow_source_sha"]
            or artifact_run.get("head_branch") != args.project_default_branch
        ):
            fail("live result artifact is not bound to the declared workflow run")
        transport_summary = f"artifact={coordinates['artifact_id']}"
    else:
        release_json = getattr(args, "release_json", None)
        release_asset_json = getattr(args, "release_asset_json", None)
        tag_ref_json = getattr(args, "tag_ref_json", None)
        if not release_json or not release_asset_json or not tag_ref_json:
            fail("independent live validation requires public release, asset, and tag API metadata")
        release_value = load_json_object(Path(release_json), "GitHub release response")
        release_id = int(coordinates["release_id"])
        release_asset_id = int(coordinates["release_asset_id"])
        release_tag = coordinates["release_tag"]
        expected_release_api = (
            f"https://api.github.com/repos/{coordinates['repository']}/releases/{release_id}"
        )
        if (
            release_value.get("id") != release_id
            or release_value.get("url") != expected_release_api
            or release_value.get("html_url") != record["release_url"]
            or release_value.get("tag_name") != release_tag
            or release_value.get("target_commitish") != record["workflow_source_sha"]
            or release_value.get("draft") is not False
            or release_value.get("prerelease") is not False
            or release_value.get("immutable") is not True
        ):
            fail("independent evidence release is not the declared immutable exact-commit release")
        release_assets = release_value.get("assets")
        if not isinstance(release_assets, list):
            fail("independent evidence release assets are malformed")
        selected = [
            asset
            for asset in release_assets
            if isinstance(asset, dict) and asset.get("id") == release_asset_id
        ]
        if len(selected) != 1:
            fail("independent evidence release asset ID is absent or duplicated")
        asset_api = load_json_object(
            Path(release_asset_json), "GitHub release asset response"
        )
        expected_asset_api = (
            f"https://api.github.com/repos/{coordinates['repository']}/releases/assets/{release_asset_id}"
        )
        for asset_label, asset in (
            ("release assets inventory", selected[0]),
            ("release asset endpoint", asset_api),
        ):
            if (
                asset.get("id") != release_asset_id
                or asset.get("url") != expected_asset_api
                or asset.get("name") != record["evidence_artifact_name"]
                or asset.get("state") != "uploaded"
                or asset.get("browser_download_url") != record["evidence_url"]
                or asset.get("digest") != f"sha256:{record['evidence_sha256']}"
                or isinstance(asset.get("size"), bool)
                or not isinstance(asset.get("size"), int)
                or asset["size"] != archive_path.stat().st_size
            ):
                fail(f"independent evidence {asset_label} metadata mismatch")
        tag_ref = load_json_object(Path(tag_ref_json), "GitHub release tag ref response")
        tag_object = tag_ref.get("object")
        expected_ref_api = (
            f"https://api.github.com/repos/{coordinates['repository']}/git/refs/tags/{release_tag}"
        )
        if (
            tag_ref.get("ref") != f"refs/tags/{release_tag}"
            or tag_ref.get("url") != expected_ref_api
            or not isinstance(tag_object, dict)
            or tag_object.get("type") != "commit"
            or tag_object.get("sha") != record["workflow_source_sha"]
            or tag_object.get("url")
            != f"https://api.github.com/repos/{coordinates['repository']}/git/commits/{record['workflow_source_sha']}"
        ):
            fail("independent evidence release tag is not a lightweight exact-source tag")
        transport_summary = (
            f"release={release_id} tag={release_tag} asset={release_asset_id}"
        )
    expected_subject = qualification_attestation_subject(record)
    expected_subject_bytes = (
        json.dumps(expected_subject, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if sha256_bytes(expected_subject_bytes) != record["result_sha256"]:
        fail("attestation subject JSON digest differs from the qualification result")
    members, subject_bytes, bundle_bytes, _ = validate_receipt_rich_evidence_zip(
        archive_path,
        expected_subject_bytes,
        str(record["evidence_run_id"]),
        str(record["replay_scenario_id"]),
        int(record["replay_exit_code"]),
        int(record["replay_expected_target_exit_code"]),
        require_attestation_bundle=args.kind == "independent",
    )
    if args.kind == "independent":
        extract_output_value = getattr(args, "extract_output", None)
        if not extract_output_value:
            fail("independent live validation requires a safe extraction output")
        safe_extract_evidence_zip(archive_path, members, Path(extract_output_value))
    subject_output = Path(args.subject_output)
    if subject_output.exists():
        fail("refusing to overwrite live attestation subject")
    subject_output.write_bytes(subject_bytes)
    if args.kind == "independent":
        bundle_output_value = getattr(args, "bundle_output", None)
        if not bundle_output_value:
            fail("independent live validation requires an attestation bundle output")
        bundle_output = Path(bundle_output_value)
        if bundle_output.exists():
            fail("refusing to overwrite live attestation bundle")
        assert bundle_bytes is not None
        bundle_output.write_bytes(bundle_bytes)
    print(
        f"PASS live_result={args.kind} repository={coordinates['repository']} "
        f"run={coordinates['run_id']} {transport_summary}"
    )


def create_candidate(args: argparse.Namespace) -> None:
    directory = Path(args.directory)
    lock_path = Path(args.lock)
    validate_version(args.version)
    if not GIT_SHA_RE.fullmatch(args.source_sha):
        fail("source SHA must be a lowercase 40-character Git object ID")
    if not args.run_id.isdigit() or int(args.run_id) <= 0:
        fail("run ID must be a positive integer")
    if not args.run_attempt.isdigit() or int(args.run_attempt) <= 0:
        fail("run attempt must be a positive integer")
    payload = candidate_payload_names(args.version)
    ensure_exact_files(directory, payload)
    for name in payload:
        require_regular_file(directory / name, name)
    load_json_object(directory / SBOM_NAME, "SBOM")
    repository_parts = args.repository.split("/")
    if len(repository_parts) != 2 or not all(SAFE_NAME_RE.fullmatch(part) for part in repository_parts):
        fail("repository must be a canonical owner/name slug")
    validate_frozen_external_snapshot(
        directory / EXTERNAL_SNAPSHOT,
        args.version,
        repository_parts[0],
    )
    validate_run_binding_file(
        directory / CANDIDATE_RUN_BINDING_NAME,
        args.run_id,
        int(args.run_attempt),
        args.workflow_ref,
        expected_dispatch_binding_inputs("candidate"),
    )
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        fail("Cargo.lock contains no packages")
    files = [file_record(directory / name) for name in sorted(payload)]
    manifest = {
        "artifact_name": ARTIFACT_NAME,
        "build_tools": {
            "packager": "scripts/release/release.py",
            "rust_toolchain": args.rust_toolchain,
            "sbom_generator": f"cargo-cyclonedx {args.sbom_tool_version}",
            "sbom_schema_commit": args.sbom_schema_commit,
            "jsonschema": args.jsonschema_version,
            "source_date_epoch": args.source_date_epoch,
        },
        "cargo_lock": {
            "package_count": len(packages),
            "sha256": sha256_file(lock_path),
        },
        "files": files,
        "kind": CANDIDATE_KIND,
        "repository": args.repository,
        "schema_version": 1,
        "source_sha": args.source_sha,
        "version": args.version,
        "workflow": {
            "ref": args.workflow_ref,
            "run_attempt": int(args.run_attempt),
            "run_id": int(args.run_id),
        },
    }
    write_json(directory / MANIFEST_NAME, manifest)
    print(sha256_file(directory / MANIFEST_NAME))


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    required = {
        "artifact_name",
        "build_tools",
        "cargo_lock",
        "files",
        "kind",
        "repository",
        "schema_version",
        "source_sha",
        "version",
        "workflow",
    }
    if set(manifest) != required:
        fail("candidate manifest has unknown or missing top-level fields")
    if manifest["schema_version"] != 1 or manifest["kind"] != CANDIDATE_KIND:
        fail("unsupported candidate manifest schema or kind")
    if manifest["artifact_name"] != ARTIFACT_NAME:
        fail("candidate manifest artifact name mismatch")
    tools = manifest["build_tools"]
    if not isinstance(tools, dict) or set(tools) != {
        "jsonschema",
        "packager",
        "rust_toolchain",
        "sbom_generator",
        "sbom_schema_commit",
        "source_date_epoch",
    }:
        fail("candidate manifest build tool identity is malformed")
    validate_version(str(manifest["version"]))
    if not GIT_SHA_RE.fullmatch(str(manifest["source_sha"])):
        fail("candidate manifest source SHA is invalid")


def verify_candidate_directory(
    directory: Path,
    expected_manifest_sha256: str | None = None,
    expected_source_sha: str | None = None,
    expected_run_id: str | None = None,
    expected_version: str | None = None,
    expected_repository: str | None = None,
    lock_path: Path | None = None,
    allow_attestation: bool = False,
    inventory_extras: Iterable[str] = (),
) -> dict[str, Any]:
    manifest_path = directory / MANIFEST_NAME
    manifest = load_json_object(manifest_path, "candidate manifest")
    validate_manifest_shape(manifest)
    version = str(manifest["version"])
    if allow_attestation:
        expected_files = release_file_names(version)
    else:
        expected_files = sorted(candidate_file_names(version) + list(inventory_extras))
    ensure_exact_files(directory, expected_files)
    manifest_digest = sha256_file(manifest_path)
    if expected_manifest_sha256 is not None:
        if not SHA256_RE.fullmatch(expected_manifest_sha256):
            fail("expected candidate manifest digest is invalid")
        if manifest_digest != expected_manifest_sha256:
            fail("candidate manifest digest mismatch")
    comparisons = {
        "source SHA": (expected_source_sha, manifest["source_sha"]),
        "version": (expected_version, version),
        "repository": (expected_repository, manifest["repository"]),
    }
    for label, (expected, actual) in comparisons.items():
        if expected is not None and expected != actual:
            fail(f"candidate {label} mismatch: expected={expected}, actual={actual}")
    workflow = manifest.get("workflow")
    if not isinstance(workflow, dict) or set(workflow) != {"ref", "run_attempt", "run_id"}:
        fail("candidate workflow identity is malformed")
    if (
        isinstance(workflow["run_id"], bool)
        or not isinstance(workflow["run_id"], int)
        or workflow["run_id"] <= 0
        or isinstance(workflow["run_attempt"], bool)
        or not isinstance(workflow["run_attempt"], int)
        or workflow["run_attempt"] <= 0
        or not isinstance(workflow["ref"], str)
        or not workflow["ref"].strip()
    ):
        fail("candidate workflow identity values are invalid")
    if expected_run_id is not None and str(workflow["run_id"]) != expected_run_id:
        fail("candidate workflow run ID mismatch")
    validate_run_binding_file(
        directory / CANDIDATE_RUN_BINDING_NAME,
        str(workflow["run_id"]),
        workflow["run_attempt"],
        workflow["ref"],
        expected_dispatch_binding_inputs("candidate"),
    )
    records = manifest.get("files")
    if not isinstance(records, list):
        fail("candidate manifest files must be an array")
    expected_record_names = sorted(candidate_payload_names(version))
    actual_record_names: list[str] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            fail("candidate manifest file record is malformed")
        name = str(record["path"])
        validate_safe_name(name, "candidate file name")
        actual_record_names.append(name)
        path = directory / name
        require_regular_file(path, "candidate file")
        if record["sha256"] != sha256_file(path) or record["size"] != path.stat().st_size:
            fail(f"candidate file record mismatch: {name}")
    if actual_record_names != expected_record_names:
        fail("candidate manifest file records are not the exact sorted inventory")
    lock_identity = manifest.get("cargo_lock")
    if not isinstance(lock_identity, dict) or set(lock_identity) != {"package_count", "sha256"}:
        fail("candidate Cargo.lock identity is malformed")
    if lock_path is not None:
        require_regular_file(lock_path, "Cargo.lock")
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        packages = lock.get("package")
        if lock_identity["sha256"] != sha256_file(lock_path):
            fail("candidate Cargo.lock digest mismatch")
        if not isinstance(packages, list) or lock_identity["package_count"] != len(packages):
            fail("candidate Cargo.lock package count mismatch")
        validate_sbom_file(
            directory / SBOM_NAME,
            lock_path,
            "tomorrowci-workspace",
            version,
        )
    repository = str(manifest["repository"])
    repository_parts = repository.split("/")
    if len(repository_parts) != 2:
        fail("candidate repository identity is malformed")
    validate_frozen_external_snapshot(
        directory / EXTERNAL_SNAPSHOT,
        version,
        repository_parts[0],
    )
    return manifest


def verify_candidate(args: argparse.Namespace) -> None:
    manifest = verify_candidate_directory(
        Path(args.directory),
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_source_sha=args.expected_source_sha,
        expected_run_id=args.expected_run_id,
        expected_version=args.expected_version,
        expected_repository=args.expected_repository,
        lock_path=Path(args.lock) if args.lock else None,
    )
    print(
        f"PASS candidate_version={manifest['version']} source_sha={manifest['source_sha']} "
        f"files={len(candidate_file_names(str(manifest['version'])))}"
    )


def parse_tag_fields(message: str) -> tuple[str, str, str, str, str, str]:
    fields: dict[str, list[str]] = {
        "candidate-artifact-digest": [],
        "candidate-run-id": [],
        "candidate-manifest-sha256": [],
        "qualification-artifact-digest": [],
        "qualification-run-id": [],
        "qualification-index-sha256": [],
    }
    for line in message.splitlines():
        for name in fields:
            prefix = f"{name}:"
            if line.startswith(prefix):
                fields[name].append(line[len(prefix) :].strip())
    for name, values in fields.items():
        if len(values) != 1:
            fail(f"annotated tag must contain exactly one {name} field")
    run_id = fields["candidate-run-id"][0]
    digest = fields["candidate-manifest-sha256"][0]
    artifact_digest = fields["candidate-artifact-digest"][0]
    qualification_run_id = fields["qualification-run-id"][0]
    qualification_digest = fields["qualification-index-sha256"][0]
    qualification_artifact_digest = fields["qualification-artifact-digest"][0]
    if not run_id.isdigit() or int(run_id) <= 0:
        fail("candidate-run-id must be a positive integer")
    if not SHA256_RE.fullmatch(digest):
        fail("candidate-manifest-sha256 must be a lowercase SHA-256 digest")
    if not ARTIFACT_DIGEST_RE.fullmatch(artifact_digest):
        fail("candidate-artifact-digest must be a canonical sha256 digest")
    if not qualification_run_id.isdigit() or int(qualification_run_id) <= 0:
        fail("qualification-run-id must be a positive integer")
    if not SHA256_RE.fullmatch(qualification_digest):
        fail("qualification-index-sha256 must be a lowercase SHA-256 digest")
    if not ARTIFACT_DIGEST_RE.fullmatch(qualification_artifact_digest):
        fail("qualification-artifact-digest must be a canonical sha256 digest")
    return (
        run_id,
        digest,
        artifact_digest,
        qualification_run_id,
        qualification_digest,
        qualification_artifact_digest,
    )


def append_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for name, value in values.items():
            if "\n" in value or "\r" in value:
                fail(f"multiline GitHub output is forbidden: {name}")
            handle.write(f"{name}={value}\n")


def parse_tag(args: argparse.Namespace) -> None:
    if not TAG_RE.fullmatch(args.tag_name):
        fail("release tag must be exactly vX.Y.Z")
    (
        run_id,
        digest,
        artifact_digest,
        qualification_run_id,
        qualification_digest,
        qualification_artifact_digest,
    ) = parse_tag_fields(Path(args.message).read_text(encoding="utf-8"))
    values = {
        "candidate_artifact_digest": artifact_digest,
        "candidate_run_id": run_id,
        "candidate_manifest_sha256": digest,
        "qualification_artifact_digest": qualification_artifact_digest,
        "qualification_run_id": qualification_run_id,
        "qualification_index_sha256": qualification_digest,
        "version": args.tag_name[1:],
    }
    if args.github_output:
        append_github_output(Path(args.github_output), values)
    print(json.dumps(values, sort_keys=True))


def validate_run(args: argparse.Namespace) -> None:
    run = load_json_object(Path(args.run_json), "workflow run response")
    artifacts = load_json_object(Path(args.artifacts_json), "workflow artifacts response")
    expected_values = {
        "id": int(args.run_id),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": args.source_sha,
        "head_branch": args.default_branch,
        "path": ".github/workflows/release.yml",
    }
    for field, expected in expected_values.items():
        if run.get(field) != expected:
            fail(f"workflow run {field} mismatch: expected={expected!r}, actual={run.get(field)!r}")
    repository = run.get("repository")
    if not isinstance(repository, dict) or repository.get("full_name") != args.repository:
        fail("workflow run repository mismatch")
    workflow_ref = f"{args.repository}/.github/workflows/release.yml@refs/heads/{args.default_branch}"
    if args.expected_workflow_ref != workflow_ref:
        fail(
            f"workflow ref mismatch: expected={args.expected_workflow_ref!r}, "
            f"actual={workflow_ref!r}"
        )
    run_attempt = run.get("run_attempt")
    if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt <= 0:
        fail("workflow run attempt is missing or invalid")
    if args.expected_run_attempt is not None and run_attempt != int(args.expected_run_attempt):
        fail("workflow run attempt does not match the frozen identity")
    binding_inputs = expected_dispatch_binding_inputs(
        args.expected_mode,
        args.expected_candidate_run_id,
        args.expected_candidate_manifest_sha256,
        args.expected_qualification_input_sha256 or "",
    )
    validate_run_binding_file(
        Path(args.input_binding),
        args.run_id,
        run_attempt,
        workflow_ref,
        binding_inputs,
    )

    # GitHub's workflow-run REST representation currently omits dispatch inputs.
    # If a future API returns them, cross-check them as an additional server signal.
    inputs = run.get("inputs")
    if inputs is not None:
        expected_input_fields = {
            "candidate_manifest_sha256",
            "candidate_run_id",
            "dry_run",
            "mode",
            "qualification_index_json",
        }
        if not isinstance(inputs, dict) or set(inputs) != expected_input_fields:
            fail("workflow_dispatch inputs have unknown or missing fields")

        def normalized_input(field: str) -> str:
            value = inputs.get(field)
            if isinstance(value, bool):
                return "true" if value else "false"
            if value is None:
                return ""
            if not isinstance(value, str):
                fail(f"workflow input {field} is not a string or boolean")
            return value

        if normalized_input("mode") != args.expected_mode or normalized_input("dry_run") != "true":
            fail("workflow dispatch mode/dry_run inputs do not match the authorized path")
        if normalized_input("candidate_run_id") != binding_inputs["candidate_run_id"]:
            fail("workflow dispatch candidate run ID differs from the attested binding")
        if normalized_input("candidate_manifest_sha256") != binding_inputs["candidate_manifest_sha256"]:
            fail("workflow dispatch candidate manifest differs from the attested binding")
        qualification_input = normalized_input("qualification_index_json")
        if args.expected_mode == "candidate":
            if qualification_input:
                fail("candidate dispatch must leave qualification_index_json empty")
        elif hashlib.sha256(qualification_input.encode("utf-8")).hexdigest() != binding_inputs[
            "qualification_index_sha256"
        ]:
            fail("workflow dispatch qualification input differs from the attested binding")

    if args.require_referenced_workflow:
        referenced = run.get("referenced_workflows")
        if not isinstance(referenced, list):
            fail("candidate run does not expose reusable acceptance workflow metadata")
        expected_path = f"{args.repository}/{args.require_referenced_workflow}"
        found = False
        for workflow in referenced:
            if not isinstance(workflow, dict):
                continue
            path = workflow.get("path")
            sha = workflow.get("sha")
            if isinstance(path, str) and path.split("@", 1)[0] == expected_path and (
                sha == args.source_sha or path.endswith(f"@{args.source_sha}")
            ):
                found = True
        if not found:
            fail("candidate run is not bound to the required reusable acceptance workflow")
    candidates = [
        artifact
        for artifact in artifacts.get("artifacts", [])
        if isinstance(artifact, dict) and artifact.get("name") == args.artifact_name
    ]
    if len(candidates) != 1:
        fail(f"workflow run must have exactly one {args.artifact_name} artifact")
    artifact = candidates[0]
    if artifact.get("expired") is not False or int(artifact.get("size_in_bytes", 0)) <= 0:
        fail("candidate artifact is expired or empty")
    artifact_id = artifact.get("id")
    if isinstance(artifact_id, bool) or not isinstance(artifact_id, int) or artifact_id <= 0:
        fail("workflow artifact ID is invalid")
    artifact_digest = artifact.get("digest")
    if not isinstance(artifact_digest, str) or not ARTIFACT_DIGEST_RE.fullmatch(artifact_digest):
        fail("workflow artifact has no canonical server-side digest")
    if args.expected_artifact_digest is not None and artifact_digest != args.expected_artifact_digest:
        fail("workflow artifact server-side digest mismatch")
    artifact_run = artifact.get("workflow_run")
    if not isinstance(artifact_run, dict) or any(
        (
            artifact_run.get("id") != int(args.run_id),
            artifact_run.get("head_sha") != args.source_sha,
            artifact_run.get("head_branch") != args.default_branch,
        )
    ):
        fail("workflow artifact is not bound to the validated run identity")
    if args.github_output:
        append_github_output(
            Path(args.github_output),
            {
                "artifact_digest": artifact_digest,
                "artifact_id": str(artifact_id),
                "run_attempt": str(run_attempt),
                "workflow_ref": workflow_ref,
            },
        )
    print(
        f"PASS workflow_run={args.run_id} attempt={run_attempt} "
        f"artifact_id={artifact_id} artifact_digest={artifact_digest}"
    )


def create_promotion(args: argparse.Namespace) -> None:
    directory = Path(args.directory)
    manifest = verify_candidate_directory(
        directory,
        expected_manifest_sha256=args.candidate_manifest_sha256,
        expected_source_sha=args.peeled_commit_sha,
        expected_run_id=args.candidate_run_id,
        expected_version=args.tag_name[1:] if TAG_RE.fullmatch(args.tag_name) else None,
        expected_repository=args.repository,
        lock_path=Path(args.lock),
        inventory_extras=[QUALIFICATION_NAME, QUALIFICATION_RUN_BINDING_NAME],
    )
    if not TAG_RE.fullmatch(args.tag_name):
        fail("release tag must be exactly vX.Y.Z")
    for label, value in (
        ("tag object SHA", args.tag_object_sha),
        ("peeled commit SHA", args.peeled_commit_sha),
    ):
        if not GIT_SHA_RE.fullmatch(value):
            fail(f"{label} is invalid")
    validate_qualification_index_file(
        directory / QUALIFICATION_NAME,
        directory / EXTERNAL_SNAPSHOT,
        args.peeled_commit_sha,
        args.candidate_manifest_sha256,
        args.candidate_artifact_digest,
        str(manifest["version"]),
        args.project_owner,
        args.repository,
        expected_digest=args.qualification_index_sha256,
    )
    validate_qualification_run_binding(
        directory / QUALIFICATION_RUN_BINDING_NAME,
        args.repository,
        args.qualification_run_id,
        args.candidate_run_id,
        args.candidate_manifest_sha256,
        args.qualification_index_sha256,
    )
    for label, value in (
        ("candidate artifact digest", args.candidate_artifact_digest),
        ("qualification artifact digest", args.qualification_artifact_digest),
    ):
        if not ARTIFACT_DIGEST_RE.fullmatch(value):
            fail(f"{label} is invalid")
    attestation = {
        "candidate": {
            "artifact_digest": args.candidate_artifact_digest,
            "manifest_sha256": args.candidate_manifest_sha256,
            "run_id": int(args.candidate_run_id),
        },
        "kind": PROMOTION_KIND,
        "qualification": {
            "artifact_digest": args.qualification_artifact_digest,
            "index_sha256": args.qualification_index_sha256,
            "run_id": int(args.qualification_run_id),
        },
        "promotion_workflow": {
            "ref": args.workflow_ref,
            "run_attempt": int(args.run_attempt),
            "run_id": int(args.run_id),
        },
        "repository": args.repository,
        "schema_version": 1,
        "source_sha": manifest["source_sha"],
        "tag": {
            "name": args.tag_name,
            "object_sha": args.tag_object_sha,
            "peeled_commit_sha": args.peeled_commit_sha,
        },
    }
    output = Path(args.output)
    if output.exists():
        fail(f"refusing to overwrite promotion attestation: {output}")
    write_json(output, attestation)
    create_checksums(
        directory,
        sorted(set(release_file_names(str(manifest["version"]))) - {CHECKSUMS_NAME}),
    )
    print(sha256_file(output))


def verify_release(args: argparse.Namespace) -> None:
    directory = Path(args.directory)
    manifest = verify_candidate_directory(
        directory,
        expected_manifest_sha256=args.candidate_manifest_sha256,
        expected_source_sha=args.peeled_commit_sha,
        expected_run_id=args.candidate_run_id,
        expected_version=args.tag_name[1:] if TAG_RE.fullmatch(args.tag_name) else None,
        expected_repository=args.repository,
        lock_path=Path(args.lock),
        allow_attestation=True,
    )
    validate_qualification_index_file(
        directory / QUALIFICATION_NAME,
        directory / EXTERNAL_SNAPSHOT,
        args.peeled_commit_sha,
        args.candidate_manifest_sha256,
        args.candidate_artifact_digest,
        str(manifest["version"]),
        args.project_owner,
        args.repository,
        expected_digest=args.qualification_index_sha256,
    )
    validate_qualification_run_binding(
        directory / QUALIFICATION_RUN_BINDING_NAME,
        args.repository,
        args.qualification_run_id,
        args.candidate_run_id,
        args.candidate_manifest_sha256,
        args.qualification_index_sha256,
    )
    attestation = load_json_object(directory / ATTESTATION_NAME, "tag promotion attestation")
    required = {
        "candidate",
        "kind",
        "promotion_workflow",
        "qualification",
        "repository",
        "schema_version",
        "source_sha",
        "tag",
    }
    if set(attestation) != required or attestation.get("schema_version") != 1 or attestation.get("kind") != PROMOTION_KIND:
        fail("tag promotion attestation schema mismatch")
    if attestation.get("repository") != args.repository or attestation.get("source_sha") != manifest["source_sha"]:
        fail("tag promotion attestation source identity mismatch")
    candidate = attestation.get("candidate")
    if candidate != {
        "artifact_digest": args.candidate_artifact_digest,
        "manifest_sha256": args.candidate_manifest_sha256,
        "run_id": int(args.candidate_run_id),
    }:
        fail("tag promotion attestation candidate identity mismatch")
    qualification = attestation.get("qualification")
    if qualification != {
        "artifact_digest": args.qualification_artifact_digest,
        "index_sha256": args.qualification_index_sha256,
        "run_id": int(args.qualification_run_id),
    }:
        fail("tag promotion attestation qualification identity mismatch")
    tag = attestation.get("tag")
    expected_tag = {
        "name": args.tag_name,
        "object_sha": args.tag_object_sha,
        "peeled_commit_sha": args.peeled_commit_sha,
    }
    if tag != expected_tag:
        fail("tag promotion attestation tag identity mismatch")
    checksum_records = parse_checksums(directory / CHECKSUMS_NAME)
    expected_checksum_names = sorted(
        set(release_file_names(str(manifest["version"]))) - {CHECKSUMS_NAME}
    )
    if sorted(checksum_records) != expected_checksum_names:
        fail("release SHA256SUMS does not cover every other release asset exactly once")
    for name, digest in checksum_records.items():
        if sha256_file(directory / name) != digest:
            fail(f"release checksum mismatch: {name}")
    print(f"PASS release_tag={args.tag_name} files={len(release_file_names(str(manifest['version'])))}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    package = subparsers.add_parser("package")
    package.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    package.add_argument("--binary", required=True)
    package.add_argument("--output", required=True)
    package.add_argument("--root", required=True)
    package.add_argument("--document", action="append", required=True)
    package.set_defaults(func=package_archive)

    verify_package = subparsers.add_parser("verify-archive")
    verify_package.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    verify_package.add_argument("--archive", required=True)
    verify_package.add_argument("--root", required=True)
    verify_package.add_argument("--binary-name", required=True)
    verify_package.set_defaults(func=verify_archive)

    extract = subparsers.add_parser("extract-archive")
    extract.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    extract.add_argument("--archive", required=True)
    extract.add_argument("--root", required=True)
    extract.add_argument("--binary-name", required=True)
    extract.add_argument("--destination", required=True)
    extract.set_defaults(func=extract_archive)

    acceptance = subparsers.add_parser("acceptance-runs")
    acceptance.add_argument("--evidence-root", required=True)
    acceptance.add_argument("--fixture-output", required=True)
    acceptance.add_argument("--all-output", required=True)
    acceptance.set_defaults(func=acceptance_runs)

    replay = subparsers.add_parser("prepare-replay")
    replay.add_argument("--evidence-root", required=True)
    replay.add_argument("--fixtures-root", required=True)
    replay.add_argument("--expected-source-sha", required=True)
    replay.add_argument("--github-output")
    replay.set_defaults(func=prepare_replay)

    sbom = subparsers.add_parser("validate-sbom")
    sbom.add_argument("--sbom", required=True)
    sbom.add_argument("--lock", required=True)
    sbom.add_argument("--expected-name", required=True)
    sbom.add_argument("--expected-version", required=True)
    sbom.set_defaults(func=validate_sbom)

    merge = subparsers.add_parser("merge-sboms")
    merge.add_argument("--input", action="append", required=True)
    merge.add_argument("--metadata", required=True)
    merge.add_argument("--lock", required=True)
    merge.add_argument("--output", required=True)
    merge.add_argument("--expected-version", required=True)
    merge.add_argument("--source-date-epoch", required=True)
    merge.set_defaults(func=merge_sboms)

    schema = subparsers.add_parser("validate-json-schema")
    schema.add_argument("--schema", required=True)
    schema.add_argument("--reference", action="append", required=True)
    schema.add_argument("--instance", required=True)
    schema.set_defaults(func=validate_json_schema)

    frozen = subparsers.add_parser("freeze-external-inputs")
    frozen.add_argument("--index", required=True)
    frozen.add_argument("--protocol", required=True)
    frozen.add_argument("--repository-root", required=True)
    frozen.add_argument("--output", required=True)
    frozen.set_defaults(func=copy_frozen_external_inputs)

    binding = subparsers.add_parser("create-run-binding")
    binding.add_argument("--output", required=True)
    binding.add_argument("--mode", choices=("candidate", "qualification"), required=True)
    binding.add_argument("--run-id", required=True)
    binding.add_argument("--run-attempt", required=True)
    binding.add_argument("--workflow-ref", required=True)
    binding.add_argument("--candidate-run-id", default="")
    binding.add_argument("--candidate-manifest-sha256", default="")
    binding.add_argument("--qualification-index-sha256", default="")
    binding.set_defaults(func=create_run_binding)

    candidate = subparsers.add_parser("create-candidate")
    candidate.add_argument("--directory", required=True)
    candidate.add_argument("--lock", required=True)
    candidate.add_argument("--version", required=True)
    candidate.add_argument("--source-sha", required=True)
    candidate.add_argument("--repository", required=True)
    candidate.add_argument("--run-id", required=True)
    candidate.add_argument("--run-attempt", required=True)
    candidate.add_argument("--workflow-ref", required=True)
    candidate.add_argument("--rust-toolchain", required=True)
    candidate.add_argument("--sbom-tool-version", required=True)
    candidate.add_argument("--sbom-schema-commit", required=True)
    candidate.add_argument("--jsonschema-version", required=True)
    candidate.add_argument("--source-date-epoch", required=True)
    candidate.set_defaults(func=create_candidate)

    verify = subparsers.add_parser("verify-candidate")
    verify.add_argument("--directory", required=True)
    verify.add_argument("--expected-manifest-sha256")
    verify.add_argument("--expected-source-sha")
    verify.add_argument("--expected-run-id")
    verify.add_argument("--expected-version")
    verify.add_argument("--expected-repository")
    verify.add_argument("--lock")
    verify.set_defaults(func=verify_candidate)

    tag = subparsers.add_parser("parse-tag")
    tag.add_argument("--tag-name", required=True)
    tag.add_argument("--message", required=True)
    tag.add_argument("--github-output")
    tag.set_defaults(func=parse_tag)

    run = subparsers.add_parser("validate-run")
    run.add_argument("--run-json", required=True)
    run.add_argument("--artifacts-json", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--source-sha", required=True)
    run.add_argument("--default-branch", required=True)
    run.add_argument("--repository", required=True)
    run.add_argument("--artifact-name", required=True)
    run.add_argument("--expected-artifact-digest")
    run.add_argument("--expected-run-attempt")
    run.add_argument("--expected-workflow-ref", required=True)
    run.add_argument("--input-binding", required=True)
    run.add_argument("--expected-mode", choices=("candidate", "qualification"), required=True)
    run.add_argument("--expected-candidate-run-id", default="")
    run.add_argument("--expected-candidate-manifest-sha256", default="")
    run.add_argument("--expected-qualification-input-sha256")
    run.add_argument("--require-referenced-workflow")
    run.add_argument("--github-output")
    run.set_defaults(func=validate_run)

    qualification = subparsers.add_parser("validate-qualification")
    qualification.add_argument("--index", required=True)
    qualification.add_argument("--frozen-index", required=True)
    qualification.add_argument("--expected-source-sha", required=True)
    qualification.add_argument("--expected-manifest-sha256", required=True)
    qualification.add_argument("--expected-candidate-artifact-digest", required=True)
    qualification.add_argument("--expected-version", required=True)
    qualification.add_argument("--expected-digest")
    qualification.add_argument("--project-owner", required=True)
    qualification.add_argument("--project-repository", required=True)
    qualification.set_defaults(func=validate_qualification)

    live_export = subparsers.add_parser("export-live-results")
    live_export.add_argument("--index", required=True)
    live_export.add_argument("--output", required=True)
    live_export.set_defaults(func=export_live_results)

    live_coordinates = subparsers.add_parser("live-result-coordinates")
    live_coordinates.add_argument("--record", required=True)
    live_coordinates.add_argument("--kind", choices=("project", "independent"), required=True)
    live_coordinates.add_argument("--project-owner", required=True)
    live_coordinates.set_defaults(func=print_live_result_coordinates)

    live = subparsers.add_parser("validate-live-result")
    live.add_argument("--record", required=True)
    live.add_argument("--kind", choices=("project", "independent"), required=True)
    live.add_argument("--project-owner", required=True)
    live.add_argument("--project-repository", required=True)
    live.add_argument("--candidate-source-sha", required=True)
    live.add_argument("--project-default-branch", required=True)
    live.add_argument("--repository-json", required=True)
    live.add_argument("--run-json", required=True)
    live.add_argument("--artifacts-json")
    live.add_argument("--release-json")
    live.add_argument("--release-asset-json")
    live.add_argument("--tag-ref-json")
    live.add_argument("--artifact-zip", required=True)
    live.add_argument("--subject-output", required=True)
    live.add_argument("--bundle-output")
    live.add_argument("--extract-output")
    live.set_defaults(func=validate_live_result)

    external_plan = subparsers.add_parser("external-target-plan")
    external_plan.add_argument("--candidate-dir", required=True)
    external_plan.add_argument("--expected-manifest-sha256", required=True)
    external_plan.add_argument("--expected-candidate-artifact-digest", required=True)
    external_plan.add_argument("--expected-source-sha", required=True)
    external_plan.add_argument("--expected-run-id", required=True)
    external_plan.add_argument("--expected-version", required=True)
    external_plan.add_argument("--expected-repository", required=True)
    external_plan.add_argument("--project-owner", required=True)
    external_plan.add_argument("--ecosystem", choices=("python", "node", "rust"), required=True)
    external_plan.add_argument("--lock")
    external_plan.add_argument("--github-output")
    external_plan.set_defaults(func=external_target_plan)

    external_replay = subparsers.add_parser("prepare-external-replay")
    external_replay.add_argument("--evidence-root", required=True)
    external_replay.add_argument("--checkout", required=True)
    external_replay.add_argument("--config", required=True)
    external_replay.add_argument("--config-sha256", required=True)
    external_replay.add_argument("--ecosystem", choices=("python", "node", "rust"), required=True)
    external_replay.add_argument("--repository", required=True)
    external_replay.add_argument("--source-sha", required=True)
    external_replay.add_argument("--scan-exit-code", required=True)
    external_replay.add_argument("--output", required=True)
    external_replay.add_argument("--github-output")
    external_replay.set_defaults(func=prepare_external_replay)

    external_subject = subparsers.add_parser("create-external-subject")
    external_subject.add_argument("--selection", required=True)
    external_subject.add_argument("--candidate-manifest-sha256", required=True)
    external_subject.add_argument("--candidate-artifact-digest", required=True)
    external_subject.add_argument("--candidate-source-sha", required=True)
    external_subject.add_argument("--first-replay-exit-code", required=True)
    external_subject.add_argument("--second-replay-exit-code", required=True)
    external_subject.add_argument("--evidence-artifact-name", required=True)
    external_subject.add_argument("--run-url", required=True)
    external_subject.add_argument("--run-attempt", required=True)
    external_subject.add_argument("--signer-workflow", required=True)
    external_subject.add_argument("--workflow-source-sha", required=True)
    external_subject.add_argument("--project-owner", required=True)
    external_subject.add_argument("--project-repository", required=True)
    external_subject.add_argument("--output", required=True)
    external_subject.add_argument("--github-output")
    external_subject.set_defaults(func=create_external_subject)

    external_stage = subparsers.add_parser("stage-external-evidence")
    external_stage.add_argument("--evidence-root", required=True)
    external_stage.add_argument("--selection", required=True)
    external_stage.add_argument("--subject", required=True)
    external_stage.add_argument("--output", required=True)
    external_stage.set_defaults(func=stage_external_evidence)

    external_readback = subparsers.add_parser("validate-external-evidence-archive")
    external_readback.add_argument("--artifact-zip", required=True)
    external_readback.add_argument("--expected-digest", required=True)
    external_readback.add_argument("--selection", required=True)
    external_readback.add_argument("--subject", required=True)
    external_readback.set_defaults(func=validate_external_evidence_archive)

    external_finalize = subparsers.add_parser("finalize-external-result")
    external_finalize.add_argument("--subject", required=True)
    external_finalize.add_argument("--artifact-id", required=True)
    external_finalize.add_argument("--artifact-digest", required=True)
    external_finalize.add_argument("--artifact-url", required=True)
    external_finalize.add_argument("--candidate-source-sha", required=True)
    external_finalize.add_argument("--project-owner", required=True)
    external_finalize.add_argument("--project-repository", required=True)
    external_finalize.add_argument("--output", required=True)
    external_finalize.set_defaults(func=finalize_external_result)

    external_combine = subparsers.add_parser("combine-project-results")
    external_combine.add_argument("--candidate-dir", required=True)
    external_combine.add_argument("--expected-manifest-sha256", required=True)
    external_combine.add_argument("--candidate-artifact-digest", required=True)
    external_combine.add_argument("--expected-source-sha", required=True)
    external_combine.add_argument("--expected-run-id", required=True)
    external_combine.add_argument("--expected-version", required=True)
    external_combine.add_argument("--expected-repository", required=True)
    external_combine.add_argument("--project-owner", required=True)
    external_combine.add_argument("--lock")
    external_combine.add_argument("--result", action="append", required=True)
    external_combine.add_argument("--output", required=True)
    external_combine.add_argument("--github-output")
    external_combine.set_defaults(func=combine_project_results)

    promotion = subparsers.add_parser("create-promotion")
    promotion.add_argument("--directory", required=True)
    promotion.add_argument("--output", required=True)
    promotion.add_argument("--lock", required=True)
    promotion.add_argument("--tag-name", required=True)
    promotion.add_argument("--tag-object-sha", required=True)
    promotion.add_argument("--peeled-commit-sha", required=True)
    promotion.add_argument("--candidate-run-id", required=True)
    promotion.add_argument("--candidate-manifest-sha256", required=True)
    promotion.add_argument("--candidate-artifact-digest", required=True)
    promotion.add_argument("--qualification-run-id", required=True)
    promotion.add_argument("--qualification-index-sha256", required=True)
    promotion.add_argument("--qualification-artifact-digest", required=True)
    promotion.add_argument("--project-owner", required=True)
    promotion.add_argument("--repository", required=True)
    promotion.add_argument("--run-id", required=True)
    promotion.add_argument("--run-attempt", required=True)
    promotion.add_argument("--workflow-ref", required=True)
    promotion.set_defaults(func=create_promotion)

    release = subparsers.add_parser("verify-release")
    release.add_argument("--directory", required=True)
    release.add_argument("--lock", required=True)
    release.add_argument("--tag-name", required=True)
    release.add_argument("--tag-object-sha", required=True)
    release.add_argument("--peeled-commit-sha", required=True)
    release.add_argument("--candidate-run-id", required=True)
    release.add_argument("--candidate-manifest-sha256", required=True)
    release.add_argument("--candidate-artifact-digest", required=True)
    release.add_argument("--qualification-run-id", required=True)
    release.add_argument("--qualification-index-sha256", required=True)
    release.add_argument("--qualification-artifact-digest", required=True)
    release.add_argument("--project-owner", required=True)
    release.add_argument("--repository", required=True)
    release.set_defaults(func=verify_release)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (ReleaseError, OSError, KeyError, ValueError) as error:
        print(f"release validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
