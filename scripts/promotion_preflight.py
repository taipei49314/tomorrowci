#!/usr/bin/env python3
"""Fail-closed state and read-back helpers for exact-byte release promotion.

The protected workflow owns mutation sequencing.  This module validates
immutable snapshots, exact retry states, and non-clobber boundaries.  It keeps
the GHCR tag write and final Release publish refused because the documented
mutation APIs lack the required create-only or compare-and-swap preconditions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

import candidate_manifest
import platform_qualification
import tag_promotion_attestation

SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF = re.compile(r"^refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")
AUTHORIZATION_ID = re.compile(r"^[0-9a-f]{64}$")
KIND = "tomorrowci.protected-promotion-remote-state.v1"
PUBLICATION_KIND = "tomorrowci.protected-exact-byte-publication-plan.v1"
DISABLED_STATUS = "PREPARED_ONLY_NOT_STANDALONE_PUBLISH_AUTHORITY"
ORAS_TOOL = (
    "ghcr.io/oras-project/oras@"
    "sha256:a3ce6b38d4c510ea9fdc0449b942ea44fb790f157e79b5e7e30b1e7460fe5579"
)
AUTHORIZATION_FILES = {
    "external-authorization.json",
    "external-authorization.json.sig",
    "external-qualification-evidence.json",
    "tag-promotion-attestation.json",
}
PREPARED_STATE_FILES = {
    "authorization-marker-identity.json",
    "external-authorization-receipt.json",
    "external-policy-transport-receipt.json",
    "external-policy.json",
    "external-policy.json.sig",
    "platform-consumption.json",
    "platform-identity.json",
    "publication-plan.json",
    "release-body.md",
    "remote-state.json",
    "tag-promotion-attestation.json",
}
PLATFORM_INPUT_KIND = "tomorrowci.protected-platform-qualification-input.v1"
PLATFORM_CONSUMPTION_KIND = "tomorrowci.protected-platform-consumption.v1"
PLATFORM_WORKFLOW_PATH = ".github/workflows/platform-qualification.yml"
PLATFORM_IDS = tuple(sorted(platform_qualification.PLATFORMS))
RUN_COORDINATE_FIELDS = (
    "candidate_run_attempt",
    "candidate_run_id",
    "ci_run_attempt",
    "ci_run_id",
    "platform_qualification_run_attempt",
    "platform_qualification_run_id",
)
MAX_RUN_COORDINATES_BYTES = 2048


def _load_json(path: Path, label: str) -> dict:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not dict:
        raise ValueError(f"{label} root must be an object")
    return value


def _snapshot(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ValueError(f"{label} size changed while reading")
    return data


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _page_items(path: Path, label: str) -> list[dict]:
    value = json.loads(
        _snapshot(path, label).decode("utf-8"),
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(pairs, label),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not list:
        raise ValueError(f"{label} must be an array of API pages")
    items: list[dict] = []
    for page in value:
        if type(page) is not list:
            raise ValueError(f"{label} page must be an array")
        for item in page:
            if type(item) is not dict:
                raise ValueError(f"{label} item must be an object")
            items.append(item)
    return items


def _load_json_array(path: Path, label: str) -> list:
    value = json.loads(
        _snapshot(path, label).decode("utf-8"),
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(pairs, label),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not list:
        raise ValueError(f"{label} must be an array")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]], label: str) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"{label} contains duplicate JSON key {key!r}")
        value[key] = item
    return value


def _positive(value: str, label: str) -> int:
    if type(value) is not str or not POSITIVE.fullmatch(value):
        raise ValueError(f"{label} must be a positive decimal integer")
    return int(value)


def parse_dispatch_run_coordinates(raw: str) -> dict[str, str]:
    if type(raw) is not str or not raw:
        raise ValueError("dispatch run coordinates must be a nonempty JSON string")
    if len(raw.encode("utf-8")) > MAX_RUN_COORDINATES_BYTES:
        raise ValueError("dispatch run coordinates exceed the size limit")
    value = json.loads(
        raw,
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(
            pairs, "dispatch run coordinates"
        ),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"dispatch run coordinates contain non-finite value {item}")
        ),
    )
    if type(value) is not dict or set(value) != set(RUN_COORDINATE_FIELDS):
        raise ValueError("dispatch run coordinates have an invalid field set")
    for field in RUN_COORDINATE_FIELDS:
        _positive(value[field], field.replace("_", " "))
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if raw != canonical:
        raise ValueError("dispatch run coordinates must use canonical JSON bytes")
    return value


def inspect_ci_run(
    metadata: dict,
    *,
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected CI repository or source SHA is malformed")
    expected_id = _positive(run_id, "CI run ID")
    expected_attempt = _positive(run_attempt, "CI run attempt")
    repo = metadata.get("repository")
    head_repo = metadata.get("head_repository")
    expected = {
        "id": expected_id,
        "run_attempt": expected_attempt,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "master",
        "head_sha": source_sha,
        "path": ".github/workflows/ci.yml",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"CI run {key} mismatch")
    if (
        type(repo) is not dict
        or type(head_repo) is not dict
        or repo.get("full_name") != repository
        or head_repo.get("full_name") != repository
    ):
        raise ValueError("CI run repository identity mismatch")
    return expected


def _strict_object(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{label} field inventory mismatch")
    return value


def _platform_artifact_specs(run_attempt: int, source_sha: str) -> list[dict[str, str]]:
    suffix = f"attempt-{run_attempt}-source-{source_sha}"
    specs = [
        {
            "name": f"platform-qualification-candidate-binding-{suffix}",
            "role": "candidate-binding",
            "scope": "candidate",
        }
    ]
    for platform_id in PLATFORM_IDS:
        specs.extend(
            (
                {
                    "name": f"platform-qualification-{platform_id}-{suffix}",
                    "role": "qualification",
                    "scope": platform_id,
                },
                {
                    "name": f"platform-qualification-readback-{platform_id}-{suffix}",
                    "role": "readback",
                    "scope": platform_id,
                },
            )
        )
    return sorted(specs, key=lambda item: item["name"])


def _platform_artifact_identity(
    value: object,
    *,
    expected_name: str,
    role: str,
    scope: str,
    repository: str,
    source_sha: str,
    run_id: int,
) -> dict:
    artifact = _strict_object(
        value,
        set(value) if type(value) is dict else set(),
        f"platform artifact {expected_name}",
    )
    artifact_id = artifact.get("id")
    size = artifact.get("size_in_bytes")
    digest = artifact.get("digest")
    workflow_run = artifact.get("workflow_run")
    if (
        type(artifact_id) is not int
        or isinstance(artifact_id, bool)
        or artifact_id <= 0
        or type(size) is not int
        or isinstance(size, bool)
        or size <= 0
        or type(digest) is not str
        or not SHA256.fullmatch(digest)
        or artifact.get("name") != expected_name
        or artifact.get("expired") is not False
        or type(workflow_run) is not dict
        or workflow_run.get("id") != run_id
        or workflow_run.get("head_branch") != "master"
        or workflow_run.get("head_sha") != source_sha
    ):
        raise ValueError(f"platform artifact {expected_name} identity mismatch")
    expected_url = (
        f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}/zip"
    )
    if artifact.get("archive_download_url") != expected_url:
        raise ValueError(f"platform artifact {expected_name} archive URL mismatch")
    return {
        "archive_sha256": digest,
        "archive_size": size,
        "artifact_id": artifact_id,
        "name": expected_name,
        "role": role,
        "scope": scope,
    }


def _validate_platform_identity(value: object) -> dict:
    identity = _strict_object(
        value,
        {
            "artifacts",
            "candidate",
            "kind",
            "project",
            "schema_version",
            "status",
            "workflow",
        },
        "platform qualification identity",
    )
    if (
        identity["kind"] != PLATFORM_INPUT_KIND
        or identity["schema_version"] != 1
        or identity["status"] != platform_qualification.STATUS
    ):
        raise ValueError("platform qualification identity kind/status mismatch")
    candidate = _strict_object(
        identity["candidate"],
        {
            "manifest_sha256",
            "oci_manifest_digest",
            "run_attempt",
            "run_id",
            "source_sha",
        },
        "platform candidate identity",
    )
    project = _strict_object(
        identity["project"],
        {"repository", "source_ref", "source_sha"},
        "platform project identity",
    )
    workflow = _strict_object(
        identity["workflow"],
        {"conclusion", "path", "run_attempt", "run_id"},
        "platform workflow identity",
    )
    if (
        type(candidate["run_id"]) is not int
        or isinstance(candidate["run_id"], bool)
        or candidate["run_id"] <= 0
        or type(candidate["run_attempt"]) is not int
        or isinstance(candidate["run_attempt"], bool)
        or candidate["run_attempt"] <= 0
        or type(workflow["run_id"]) is not int
        or isinstance(workflow["run_id"], bool)
        or workflow["run_id"] <= 0
        or type(workflow["run_attempt"]) is not int
        or isinstance(workflow["run_attempt"], bool)
        or workflow["run_attempt"] <= 0
        or type(project["repository"]) is not str
        or not SLUG.fullmatch(project["repository"])
        or project["source_ref"] != "refs/heads/master"
        or project["source_sha"] != candidate["source_sha"]
        or type(project["source_sha"]) is not str
        or not SHA.fullmatch(project["source_sha"])
        or not SHA256.fullmatch(str(candidate["manifest_sha256"]))
        or not SHA256.fullmatch(str(candidate["oci_manifest_digest"]))
        or workflow["path"] != PLATFORM_WORKFLOW_PATH
        or workflow["conclusion"] != "success"
    ):
        raise ValueError("platform qualification source/candidate identity mismatch")
    artifacts = identity["artifacts"]
    if type(artifacts) is not list:
        raise ValueError("platform qualification artifact identity is not an array")
    specs = _platform_artifact_specs(workflow["run_attempt"], project["source_sha"])
    if len(artifacts) != len(specs):
        raise ValueError("platform qualification artifact set is incomplete")
    expected_by_name = {item["name"]: item for item in specs}
    seen_ids: set[int] = set()
    names: list[str] = []
    for artifact in artifacts:
        item = _strict_object(
            artifact,
            {
                "archive_sha256",
                "archive_size",
                "artifact_id",
                "name",
                "role",
                "scope",
            },
            "platform artifact identity",
        )
        name = item["name"]
        spec = expected_by_name.get(name) if type(name) is str else None
        if (
            spec is None
            or item["role"] != spec["role"]
            or item["scope"] != spec["scope"]
            or type(item["artifact_id"]) is not int
            or isinstance(item["artifact_id"], bool)
            or item["artifact_id"] <= 0
            or item["artifact_id"] in seen_ids
            or type(item["archive_size"]) is not int
            or isinstance(item["archive_size"], bool)
            or item["archive_size"] <= 0
            or type(item["archive_sha256"]) is not str
            or not SHA256.fullmatch(item["archive_sha256"])
        ):
            raise ValueError("platform qualification artifact identity mismatch")
        seen_ids.add(item["artifact_id"])
        names.append(name)
    if names != sorted(expected_by_name):
        raise ValueError("platform qualification artifact order/inventory mismatch")
    return identity


def inspect_platform_api(
    run_metadata: dict,
    artifact_metadata: dict,
    *,
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
    candidate_run_id: str,
    candidate_run_attempt: str,
    candidate_manifest_sha256: str,
    oci_manifest_digest: str,
    expected_identity_sha256: str | None,
) -> dict:
    if (
        not SLUG.fullmatch(repository)
        or not SHA.fullmatch(source_sha)
        or not SHA256.fullmatch(candidate_manifest_sha256)
        or not SHA256.fullmatch(oci_manifest_digest)
        or (
            expected_identity_sha256 is not None
            and not SHA256.fullmatch(expected_identity_sha256)
        )
    ):
        raise ValueError("platform qualification dispatch identity is malformed")
    expected_run_id = _positive(run_id, "platform workflow run ID")
    expected_attempt = _positive(run_attempt, "platform workflow run attempt")
    candidate_id = _positive(candidate_run_id, "candidate run ID")
    candidate_attempt = _positive(candidate_run_attempt, "candidate run attempt")
    repository_identity = run_metadata.get("repository")
    head_repository = run_metadata.get("head_repository")
    expected_run = {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": source_sha,
        "id": expected_run_id,
        "path": PLATFORM_WORKFLOW_PATH,
        "run_attempt": expected_attempt,
        "status": "completed",
    }
    for key, expected in expected_run.items():
        if run_metadata.get(key) != expected:
            raise ValueError(f"platform qualification run {key} mismatch")
    if (
        run_metadata.get("name") != "platform-qualification"
        or type(repository_identity) is not dict
        or repository_identity.get("full_name") != repository
        or type(head_repository) is not dict
        or head_repository.get("full_name") != repository
    ):
        raise ValueError("platform qualification run repository identity mismatch")
    values = artifact_metadata.get("artifacts")
    if (
        type(values) is not list
        or artifact_metadata.get("total_count") != len(values)
        or len(values) > 100
    ):
        raise ValueError("platform artifact API response is incomplete or paginated")
    specs = _platform_artifact_specs(expected_attempt, source_sha)
    artifacts: list[dict] = []
    for spec in specs:
        matches = [
            item
            for item in values
            if type(item) is dict and item.get("name") == spec["name"]
        ]
        if len(matches) != 1:
            raise ValueError(
                f"platform artifact {spec['name']} is missing or duplicate"
            )
        artifacts.append(
            _platform_artifact_identity(
                matches[0],
                expected_name=spec["name"],
                role=spec["role"],
                scope=spec["scope"],
                repository=repository,
                source_sha=source_sha,
                run_id=expected_run_id,
            )
        )
    identity = _validate_platform_identity(
        {
            "artifacts": artifacts,
            "candidate": {
                "manifest_sha256": candidate_manifest_sha256,
                "oci_manifest_digest": oci_manifest_digest,
                "run_attempt": candidate_attempt,
                "run_id": candidate_id,
                "source_sha": source_sha,
            },
            "kind": PLATFORM_INPUT_KIND,
            "project": {
                "repository": repository,
                "source_ref": "refs/heads/master",
                "source_sha": source_sha,
            },
            "schema_version": 1,
            "status": platform_qualification.STATUS,
            "workflow": {
                "conclusion": "success",
                "path": PLATFORM_WORKFLOW_PATH,
                "run_attempt": expected_attempt,
                "run_id": expected_run_id,
            },
        }
    )
    if (
        expected_identity_sha256 is not None
        and _sha256(canonical_bytes(identity)) != expected_identity_sha256
    ):
        raise ValueError("platform qualification canonical identity digest mismatch")
    return identity


def inspect_repository_head(
    repository_metadata: dict,
    branch_metadata: dict,
    *,
    repository: str,
    source_sha: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected repository or source SHA is malformed")
    branch_object = branch_metadata.get("object")
    if (
        repository_metadata.get("full_name") != repository
        or repository_metadata.get("default_branch") != "master"
        or branch_metadata.get("ref") != "refs/heads/master"
        or type(branch_object) is not dict
        or branch_object.get("type") != "commit"
        or branch_object.get("sha") != source_sha
    ):
        raise ValueError("default branch no longer names the exact source commit")
    return {"default_branch": "master", "repository": repository, "sha": source_sha}


def inspect_promotion_workflow_run(
    metadata: dict,
    *,
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected promotion repository or source SHA is malformed")
    expected_id = _positive(run_id, "promotion run ID")
    expected_attempt = _positive(run_attempt, "promotion run attempt")
    expected = {
        "event": "workflow_dispatch",
        "head_branch": "master",
        "head_sha": source_sha,
        "id": expected_id,
        "path": ".github/workflows/protected-exact-byte-promotion-v2.yml",
        "run_attempt": expected_attempt,
        "status": "in_progress",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"promotion workflow run {key} mismatch")
    if metadata.get("conclusion") is not None:
        raise ValueError("in-progress promotion run already has a conclusion")
    repo = metadata.get("repository")
    head_repo = metadata.get("head_repository")
    actor = metadata.get("actor")
    triggering_actor = metadata.get("triggering_actor")
    if (
        type(repo) is not dict
        or type(head_repo) is not dict
        or repo.get("full_name") != repository
        or head_repo.get("full_name") != repository
        or type(actor) is not dict
        or type(actor.get("id")) is not int
        or type(triggering_actor) is not dict
        or type(triggering_actor.get("id")) is not int
    ):
        raise ValueError("promotion workflow run repository or actor identity mismatch")
    return {
        **expected,
        "actor_id": actor["id"],
        "triggering_actor_id": triggering_actor["id"],
    }


def inspect_release_environment(metadata: dict) -> dict:
    if metadata.get("name") != "release":
        raise ValueError("protected environment name mismatch")
    rules = metadata.get("protection_rules")
    if type(rules) is not list:
        raise ValueError("release environment protection rules are missing")
    reviewer_rules = [
        rule for rule in rules if rule.get("type") == "required_reviewers"
    ]
    if len(reviewer_rules) != 1:
        raise ValueError("release environment must have one required-reviewer rule")
    rule = reviewer_rules[0]
    reviewers = rule.get("reviewers")
    if (
        rule.get("prevent_self_review") is not True
        or type(reviewers) is not list
        or not reviewers
        or any(
            type(item) is not dict
            or item.get("type") not in {"User", "Team"}
            or type(item.get("reviewer")) is not dict
            or type(item["reviewer"].get("id")) is not int
            for item in reviewers
        )
    ):
        raise ValueError("release environment reviewer approval is not fail-closed")
    branch_policy = metadata.get("deployment_branch_policy")
    if (
        type(branch_policy) is not dict
        or branch_policy.get("protected_branches") is not True
        or branch_policy.get("custom_branch_policies") is not False
    ):
        raise ValueError("release environment must allow protected branches only")
    return {
        "environment": "release",
        "prevent_self_review": True,
        "required_reviewers": len(reviewers),
        "protected_branches_only": True,
    }


def inspect_approval_history(
    approvals: list,
    *,
    environment_metadata: dict,
    run_metadata: dict,
) -> dict:
    """Bind the approval identity fields exposed by the run-level REST API."""

    inspect_release_environment(environment_metadata)
    environment_id = environment_metadata.get("id")
    reviewer_rule = next(
        rule
        for rule in environment_metadata["protection_rules"]
        if rule.get("type") == "required_reviewers"
    )
    configured_reviewers = reviewer_rule["reviewers"]
    direct_user_ids = {
        item["reviewer"]["id"]
        for item in configured_reviewers
        if item.get("type") == "User"
    }
    has_team_reviewer = any(item.get("type") == "Team" for item in configured_reviewers)
    actor = run_metadata.get("actor")
    triggering_actor = run_metadata.get("triggering_actor")
    if (
        type(environment_id) is not int
        or environment_id <= 0
        or type(actor) is not dict
        or type(actor.get("id")) is not int
        or type(triggering_actor) is not dict
        or type(triggering_actor.get("id")) is not int
        or type(approvals) is not list
    ):
        raise ValueError("approval context identity is malformed")
    approvers: list[dict] = []
    for review in approvals:
        if type(review) is not dict:
            raise ValueError("approval history entry is malformed")
        environments = review.get("environments")
        if type(environments) is not list:
            raise ValueError("approval history environments are malformed")
        matches = [
            item
            for item in environments
            if type(item) is dict
            and item.get("id") == environment_id
            and item.get("name") == "release"
        ]
        if not matches:
            continue
        if (
            len(environments) != 1
            or len(matches) != 1
            or review.get("state") != "approved"
        ):
            raise ValueError("release environment review is not an exact approval")
        user = review.get("user")
        if (
            type(user) is not dict
            or type(user.get("id")) is not int
            or user["id"] <= 0
            or type(user.get("login")) is not str
            or not user["login"]
            or user["id"] in {actor["id"], triggering_actor["id"]}
            or (not has_team_reviewer and user["id"] not in direct_user_ids)
        ):
            raise ValueError("release approval identity is missing or self-approved")
        approvers.append({"id": user["id"], "login": user["login"]})
    if not approvers:
        raise ValueError("no observable independent release approval")
    identities = sorted({(item["id"], item["login"]) for item in approvers})
    return {
        "approval_history_scope": "workflow_run",
        "environment_id": environment_id,
        "reviewers": [
            {"id": reviewer_id, "login": login} for reviewer_id, login in identities
        ],
    }


def inspect_artifact(
    metadata: dict,
    *,
    artifact_id: str,
    artifact_sha256: str,
) -> dict:
    expected_id = _positive(artifact_id, "authorization artifact ID")
    if not SHA256.fullmatch(artifact_sha256):
        raise ValueError("authorization artifact digest is malformed")
    if metadata.get("id") != expected_id:
        raise ValueError("authorization artifact ID mismatch")
    if metadata.get("digest") != artifact_sha256:
        raise ValueError("authorization artifact API digest mismatch")
    if metadata.get("expired") is not False:
        raise ValueError("authorization artifact is expired")
    size = metadata.get("size_in_bytes")
    if type(size) is not int or size <= 0:
        raise ValueError("authorization artifact size is invalid")
    return {"artifact_id": expected_id, "digest": artifact_sha256, "size": size}


def inspect_oci_manifest_digest(provenance: Path, expected_digest: str) -> str:
    """Read strict JSON and bind only the authoritative OCI manifest field."""

    if not SHA256.fullmatch(expected_digest):
        raise ValueError("expected OCI manifest digest is malformed")
    document = _load_json(provenance, "OCI detached provenance")
    oci = document.get("oci")
    manifest = oci.get("manifest") if type(oci) is dict else None
    actual = manifest.get("digest") if type(manifest) is dict else None
    if type(actual) is not str or not SHA256.fullmatch(actual):
        raise ValueError("OCI detached provenance manifest digest is malformed")
    if actual != expected_digest:
        raise ValueError("OCI detached provenance manifest digest mismatch")
    return actual


def inspect_package_pages(pages: Path, *, package_name: str, owner: str) -> str:
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,127})", package_name):
        raise ValueError("GHCR package name is malformed")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise ValueError("GHCR owner is malformed")
    matches = []
    for package in _page_items(pages, "GitHub package API pages"):
        if package.get("name") == package_name:
            if package.get("package_type") != "container":
                raise ValueError("named GitHub package is not a container package")
            package_owner = package.get("owner")
            if type(package_owner) is not dict or package_owner.get("login") != owner:
                raise ValueError("GHCR package namespace mismatch")
            if package.get("visibility") not in {"private", "public"}:
                raise ValueError("GHCR package visibility is unsupported")
            matches.append(package)
    if len(matches) > 1:
        raise ValueError("GitHub package API contains duplicate package identity")
    if not matches:
        return "ABSENT"
    return f"PRESENT_{matches[0]['visibility'].upper()}"


def _attestation_assets(attestation: dict, candidate_dir: Path) -> list[dict]:
    if (
        attestation.get("kind") != tag_promotion_attestation.KIND
        or attestation.get("status") != tag_promotion_attestation.STATUS
        or attestation.get("schema_version") != 1
    ):
        raise ValueError("tag-promotion qualification identity mismatch")
    assets = attestation.get("release_assets")
    if type(assets) is not list or not assets:
        raise ValueError("tag-promotion release asset inventory is missing")
    expected: list[dict] = []
    names: list[str] = []
    for item in assets:
        if type(item) is not dict or set(item) != {"name", "sha256", "size"}:
            raise ValueError("tag-promotion release asset schema mismatch")
        name = item["name"]
        digest = item["sha256"]
        size = item["size"]
        if (
            type(name) is not str
            or Path(name).name != name
            or name in {".", ".."}
            or name == "tag-promotion-attestation.json"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}", name)
            or type(digest) is not str
            or not SHA256.fullmatch(digest)
            or type(size) is not int
            or size <= 0
        ):
            raise ValueError("tag-promotion release asset identity is malformed")
        data = _snapshot(candidate_dir / name, f"candidate release asset {name}")
        if len(data) != size or _sha256(data) != digest:
            raise ValueError(f"candidate release asset bytes disagree: {name}")
        names.append(name)
        expected.append({"name": name, "sha256": digest, "size": size})
    if names != sorted(names) or len(names) != len(set(names)):
        raise ValueError("tag-promotion release asset names are not canonical")
    actual_names = sorted(entry.name for entry in candidate_dir.iterdir())
    if actual_names != names:
        raise ValueError(
            "candidate directory does not equal the release asset inventory"
        )
    return expected


def release_body(attestation: dict, *, oci_repository: str) -> str:
    candidate = attestation.get("candidate")
    external = attestation.get("external_authorization")
    authorization = external.get("authorization") if type(external) is dict else None
    oci = attestation.get("oci")
    if (
        type(candidate) is not dict
        or type(authorization) is not dict
        or type(oci) is not dict
    ):
        raise ValueError("tag-promotion authority identity is incomplete")
    version = candidate.get("version")
    source_sha = candidate.get("source_sha")
    manifest = candidate.get("manifest_sha256")
    authorization_id = authorization.get("id")
    image_digest = oci.get("manifest_sha256")
    if (
        type(version) is not str
        or not re.fullmatch(r"[0-9A-Za-z.-]+", version)
        or type(source_sha) is not str
        or not SHA.fullmatch(source_sha)
        or type(manifest) is not str
        or not SHA256.fullmatch(manifest)
        or type(authorization_id) is not str
        or not AUTHORIZATION_ID.fullmatch(authorization_id)
        or type(image_digest) is not str
        or not SHA256.fullmatch(image_digest)
        or not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+", oci_repository)
    ):
        raise ValueError("tag-promotion release-note identity is malformed")
    return (
        f"Protected exact-byte prerelease for TomorrowCI v{version}.\n\n"
        f"- Source: `{source_sha}`\n"
        f"- Candidate manifest: `{manifest}`\n"
        f"- External authorization: `{authorization_id}`\n"
        f"- OCI image: `{oci_repository}@{image_digest}`\n\n"
        "Assets and image bytes are promoted from the verified candidate without rebuilding.\n"
    )


def inspect_release_state(
    releases: list[dict],
    *,
    tag_name: str,
    target_commitish: str,
    release_name: str,
    body: str,
    expected_assets: list[dict],
) -> dict:
    matches = [release for release in releases if release.get("tag_name") == tag_name]
    if len(matches) > 1:
        raise ValueError("GitHub Releases API contains duplicate tag identity")
    if not matches:
        return {
            "missing_assets": [item["name"] for item in expected_assets],
            "state": "CREATE_NONCLOBBER_DRAFT_PRERELEASE",
        }
    release = matches[0]
    expected_fields = {
        "name": release_name,
        "body": body,
        "tag_name": tag_name,
        "prerelease": True,
    }
    for key, value in expected_fields.items():
        if release.get(key) != value:
            raise ValueError(f"GitHub Release {key} drift")
    # GitHub may normalize target_commitish to the default branch after the tag
    # exists.  The separately verified annotated tag object is authoritative.
    if (
        type(release.get("target_commitish")) is not str
        or not release["target_commitish"]
    ):
        raise ValueError("GitHub Release target_commitish is malformed")
    if type(release.get("id")) is not int or release["id"] <= 0:
        raise ValueError("GitHub Release ID is invalid")
    observed_assets = release.get("assets")
    if type(observed_assets) is not list:
        raise ValueError("GitHub Release assets are missing")
    expected_by_name = {item["name"]: item for item in expected_assets}
    seen: set[str] = set()
    for asset in observed_assets:
        if type(asset) is not dict or type(asset.get("name")) is not str:
            raise ValueError("GitHub Release asset metadata is malformed")
        name = asset["name"]
        if name in seen or name not in expected_by_name:
            raise ValueError("GitHub Release contains duplicate or unexpected asset")
        seen.add(name)
        expected = expected_by_name[name]
        if (
            asset.get("size") != expected["size"]
            or asset.get("digest") != expected["sha256"]
        ):
            raise ValueError(f"GitHub Release asset bytes drift: {name}")
    missing = sorted(set(expected_by_name) - seen)
    draft = release.get("draft")
    immutable = release.get("immutable")
    if draft is True and immutable is False:
        return {
            "missing_assets": missing,
            "release_id": release["id"],
            "state": "RESUME_EXACT_NONCLOBBER_DRAFT" if missing else "DRAFT_COMPLETE",
        }
    if draft is False and immutable is True and not missing:
        return {
            "missing_assets": [],
            "release_id": release["id"],
            "state": "IDEMPOTENT_EXACT_IMMUTABLE_PRERELEASE",
        }
    raise ValueError("GitHub Release is neither an exact draft nor immutable release")


def inspect_immutable_release_setting(metadata: dict) -> None:
    """Require the repository immutable-releases control to be explicitly enabled."""

    if type(metadata) is not dict or metadata.get("enabled") is not True:
        raise ValueError("repository immutable releases are not enabled")


def inspect_ghcr_state(
    versions: list[dict], *, image_tag: str, manifest_digest: str
) -> dict:
    if not re.fullmatch(r"v[0-9A-Za-z.-]+", image_tag) or not SHA256.fullmatch(
        manifest_digest
    ):
        raise ValueError("expected GHCR tag or digest is malformed")
    tagged_digest: str | None = None
    digest_present = False
    if len(versions) > 1:
        raise ValueError("GHCR repository contains unexpected additional versions")
    for version in versions:
        name = version.get("name")
        metadata = version.get("metadata")
        container = metadata.get("container") if type(metadata) is dict else None
        if (
            type(name) is not str
            or not SHA256.fullmatch(name)
            or type(metadata) is not dict
            or metadata.get("package_type") != "container"
            or type(container) is not dict
            or type(container.get("tags")) is not list
            or any(type(tag) is not str for tag in container["tags"])
        ):
            raise ValueError("GHCR package version metadata is malformed")
        if name != manifest_digest or any(
            tag != image_tag for tag in container["tags"]
        ):
            raise ValueError("GHCR repository contains an unrelated digest or tag")
        if name == manifest_digest:
            digest_present = True
        if image_tag in container["tags"]:
            if tagged_digest is not None:
                raise ValueError("GHCR tag appears on multiple manifest digests")
            tagged_digest = name
    if tagged_digest is not None and tagged_digest != manifest_digest:
        raise ValueError("GHCR tag already names a different manifest digest")
    if tagged_digest == manifest_digest:
        state = "IDEMPOTENT_EXACT_IMAGE"
    elif digest_present:
        state = "READY_TO_ADD_EXACT_TAG"
    else:
        state = "READY_FOR_EXACT_OCI_COPY"
    return {"manifest_digest": manifest_digest, "state": state, "tag": image_tag}


def inspect_public_asset_readback(directory: Path, expected_assets: list[dict]) -> None:
    actual = sorted(entry.name for entry in directory.iterdir())
    expected = [item["name"] for item in expected_assets]
    if actual != expected:
        raise ValueError("public release download inventory mismatch")
    for item in expected_assets:
        data = _snapshot(
            directory / item["name"], f"downloaded release asset {item['name']}"
        )
        if len(data) != item["size"] or _sha256(data) != item["sha256"]:
            raise ValueError(f"public release asset read-back mismatch: {item['name']}")


def inspect_public_oci_descriptor(descriptor: Path, expected_digest: str) -> dict:
    if not SHA256.fullmatch(expected_digest):
        raise ValueError("expected public OCI digest is malformed")
    value = _load_json(descriptor, "public OCI descriptor")
    if set(value) != {"digest", "mediaType", "size"}:
        raise ValueError("public OCI descriptor schema mismatch")
    if (
        value["digest"] != expected_digest
        or value["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
        or type(value["size"]) is not int
        or value["size"] <= 0
    ):
        raise ValueError("public OCI descriptor identity mismatch")
    return value


def inspect_http_etag(headers: Path) -> str:
    raw = _snapshot(headers, "HTTP response headers")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("HTTP response headers are not ASCII") from exc
    values = []
    for line in text.replace("\r\n", "\n").split("\n"):
        name, separator, value = line.partition(":")
        if separator and name.lower() == "etag":
            values.append(value.strip())
    if len(values) != 1 or not re.fullmatch(
        r'(?:W/)?"[A-Za-z0-9._~:/+=-]{1,200}"', values[0]
    ):
        raise ValueError("HTTP response has no single safe ETag")
    return values[0]


def inspect_doctor_output(output: Path, *, expected_version: str) -> dict:
    if not re.fullmatch(r"[0-9A-Za-z.-]+", expected_version):
        raise ValueError("expected doctor version is malformed")
    try:
        lines = _snapshot(output, "doctor output").decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("doctor output is not UTF-8") from exc
    if not lines or lines[0] != "TomorrowCI doctor":
        raise ValueError("doctor output header mismatch")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.startswith("note: "):
            continue
        key, separator, value = line.partition(": ")
        if not separator or key in fields:
            raise ValueError("doctor output contains malformed or duplicate fields")
        fields[key] = value
    required = {
        "docker",
        "host_execution_of_targets",
        "podman",
        "security_defaults",
        "selected_engine",
        "status",
        "tool_version",
    }
    if set(fields) != required:
        raise ValueError("doctor output field inventory mismatch")
    if (
        fields["tool_version"] != expected_version
        or fields["docker"] not in {"true", "false"}
        or fields["podman"] not in {"true", "false"}
        or fields["security_defaults"] != "OK"
        or fields["host_execution_of_targets"] != "FORBIDDEN by default"
    ):
        raise ValueError("doctor identity or security semantics mismatch")
    ready = fields["status"] == "READY"
    blocked = fields["status"] == "BLOCKED for container execution"
    selected = fields["selected_engine"]
    if ready:
        if selected not in {"Docker", "Podman"}:
            raise ValueError("READY doctor output has no selected engine")
        if fields[selected.lower()] != "true":
            raise ValueError("READY doctor output contradicts engine detection")
    elif blocked:
        if (
            selected != "NONE (sandbox BLOCKED)"
            or fields["docker"] != "false"
            or fields["podman"] != "false"
        ):
            raise ValueError("BLOCKED doctor output is not honest about engines")
    else:
        raise ValueError("doctor status is neither READY nor honest BLOCKED")
    return {"selected_engine": selected, "status": fields["status"]}


def _load_platform_identity(path: Path) -> tuple[dict, bytes]:
    data = _snapshot(path, "platform qualification identity")
    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=lambda pairs: _reject_duplicate_pairs(
            pairs, "platform qualification identity"
        ),
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(
                f"platform qualification identity contains non-finite JSON value {item}"
            )
        ),
    )
    identity = _validate_platform_identity(value)
    if data != canonical_bytes(identity):
        raise ValueError("platform qualification identity is not canonical JSON")
    return identity, data


def _artifact_from_identity(identity: dict, *, role: str, scope: str) -> dict:
    matches = [
        item
        for item in identity["artifacts"]
        if item["role"] == role and item["scope"] == scope
    ]
    if len(matches) != 1:
        raise ValueError(f"platform artifact identity missing for {role}/{scope}")
    return matches[0]


def _platform_observation_bytes(identity: dict, *, role: str, scope: str) -> bytes:
    project = identity["project"]
    candidate = identity["candidate"]
    workflow = identity["workflow"]
    common = [
        f"repository: {project['repository']}",
        f"source_sha: {project['source_sha']}",
        f"source_ref: {project['source_ref']}",
        f"workflow_run_id: {workflow['run_id']}",
        f"workflow_run_attempt: {workflow['run_attempt']}",
        f"candidate_run_id: {candidate['run_id']}",
        f"candidate_run_attempt: {candidate['run_attempt']}",
        f"candidate_source_sha: {candidate['source_sha']}",
        f"candidate_manifest_sha256: {candidate['manifest_sha256']}",
        f"oci_manifest_digest: {candidate['oci_manifest_digest']}",
    ]
    if role == "candidate-binding" and scope == "candidate":
        lines = [
            "kind: tomorrowci.platform-candidate-binding/v1",
            "status: PASS",
            *common,
        ]
    elif role == "readback" and scope in PLATFORM_IDS:
        lines = [
            "kind: tomorrowci.platform-readback/v1",
            "status: PASS",
            f"platform_id: {scope}",
            *common,
        ]
    else:
        raise ValueError("unknown platform observation role/scope")
    return ("\n".join(lines) + "\n").encode("utf-8")


def verify_platform_observation(
    root: Path, identity: dict, *, role: str, scope: str
) -> str:
    expected_name = (
        "candidate-binding-pass.txt"
        if role == "candidate-binding"
        else "readback-pass.txt"
    )
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise ValueError("cannot inspect retained platform observation") from exc
    if len(entries) != 1 or entries[0].name != expected_name:
        raise ValueError("retained platform observation inventory mismatch")
    data = _snapshot(entries[0], "retained platform PASS observation")
    if data != _platform_observation_bytes(identity, role=role, scope=scope):
        raise ValueError("retained platform PASS observation identity mismatch")
    return _sha256(data)


def _validate_platform_consumption(value: object) -> dict:
    consumption = _strict_object(
        value,
        {
            "candidate_binding",
            "identity",
            "kind",
            "platforms",
            "schema_version",
            "status",
        },
        "platform consumption",
    )
    if (
        consumption["kind"] != PLATFORM_CONSUMPTION_KIND
        or consumption["schema_version"] != 1
        or consumption["status"] != platform_qualification.STATUS
    ):
        raise ValueError("platform consumption kind/status mismatch")
    identity = _validate_platform_identity(consumption["identity"])
    binding = _strict_object(
        consumption["candidate_binding"],
        {"artifact", "observation_sha256"},
        "platform candidate-binding consumption",
    )
    if (
        binding["artifact"]
        != _artifact_from_identity(
            identity, role="candidate-binding", scope="candidate"
        )
        or type(binding["observation_sha256"]) is not str
        or not SHA256.fullmatch(binding["observation_sha256"])
    ):
        raise ValueError("platform candidate-binding consumption mismatch")
    platforms = consumption["platforms"]
    if type(platforms) is not list or len(platforms) != len(PLATFORM_IDS):
        raise ValueError("platform consumption matrix is incomplete")
    observed: list[str] = []
    for row_value in platforms:
        item = _strict_object(
            row_value,
            {
                "artifact",
                "capture_sha256",
                "engine",
                "evidence",
                "platform_id",
                "post_clean",
                "readback",
                "record_sha256",
                "runner",
            },
            "platform consumption row",
        )
        platform_id = item["platform_id"]
        if platform_id not in PLATFORM_IDS:
            raise ValueError("platform consumption has an unknown platform")
        expected_artifact = _artifact_from_identity(
            identity, role="qualification", scope=platform_id
        )
        expected_readback = _artifact_from_identity(
            identity, role="readback", scope=platform_id
        )
        readback = _strict_object(
            item["readback"],
            {"artifact", "observation_sha256"},
            "platform read-back consumption",
        )
        post_clean = _strict_object(
            item["post_clean"], {"sha256", "status"}, "platform post-clean state"
        )
        engine = item["engine"]
        runner = item["runner"]
        evidence = item["evidence"]
        spec = platform_qualification.PLATFORMS[platform_id]
        if (
            item["artifact"] != expected_artifact
            or readback["artifact"] != expected_readback
            or type(readback["observation_sha256"]) is not str
            or not SHA256.fullmatch(readback["observation_sha256"])
            or post_clean["status"] != "EMPTY"
            or type(post_clean["sha256"]) is not str
            or not SHA256.fullmatch(post_clean["sha256"])
            or type(item["record_sha256"]) is not str
            or not SHA256.fullmatch(item["record_sha256"])
            or type(item["capture_sha256"]) is not str
            or not SHA256.fullmatch(item["capture_sha256"])
            or type(engine) is not dict
            or engine.get("provider") != spec.provider
            or engine.get("context") != spec.engine_context
            or engine.get("os_type") != "linux"
            or engine.get("server_version") != engine.get("version_output")
            or type(runner) is not dict
            or runner.get("environment") != "self-hosted"
            or runner.get("os") != spec.runner_os
            or runner.get("arch") != spec.runner_arch
            or type(evidence) is not dict
            or evidence.get("replay_count") != 2
        ):
            raise ValueError(f"platform consumption row mismatch for {platform_id}")
        observed.append(platform_id)
    if observed != list(PLATFORM_IDS):
        raise ValueError("platform consumption row order/inventory mismatch")
    return consumption


def verify_platform_consumption(
    *,
    identity_path: Path,
    artifacts_root: Path,
    observations_root: Path,
    candidate_dist: Path,
    fixture_source: Path,
) -> dict:
    identity, _ = _load_platform_identity(identity_path)
    expected_artifact_dirs = list(PLATFORM_IDS)
    try:
        artifact_dirs = sorted(entry.name for entry in artifacts_root.iterdir())
        observation_dirs = sorted(entry.name for entry in observations_root.iterdir())
        readback_dirs = sorted(
            entry.name for entry in (observations_root / "readback").iterdir()
        )
    except OSError as exc:
        raise ValueError("platform consumption roots are incomplete") from exc
    if artifact_dirs != expected_artifact_dirs:
        raise ValueError("platform qualification extracted artifact matrix mismatch")
    if observation_dirs != ["candidate-binding", "readback"]:
        raise ValueError("platform observation root inventory mismatch")
    if readback_dirs != expected_artifact_dirs:
        raise ValueError("platform read-back observation matrix mismatch")
    candidate_binding_sha256 = verify_platform_observation(
        observations_root / "candidate-binding",
        identity,
        role="candidate-binding",
        scope="candidate",
    )
    rows: list[dict] = []
    candidate = identity["candidate"]
    project = identity["project"]
    workflow = identity["workflow"]
    empty_state = {"containers": [], "volumes": []}
    empty_state_bytes = platform_qualification.canonical_json_bytes(empty_state)
    for platform_id in PLATFORM_IDS:
        artifact_root = artifacts_root / platform_id
        args = argparse.Namespace(
            artifact_root=artifact_root,
            candidate_dist=candidate_dist,
            candidate_run_id=str(candidate["run_id"]),
            candidate_run_attempt=str(candidate["run_attempt"]),
            candidate_manifest_sha256=candidate["manifest_sha256"],
            candidate_source_sha=candidate["source_sha"],
            oci_manifest_digest=candidate["oci_manifest_digest"],
            platform_id=platform_id,
            fixture_source=fixture_source,
            project_repository=project["repository"],
            project_source_sha=project["source_sha"],
            project_source_ref=project["source_ref"],
            workflow_run_id=str(workflow["run_id"]),
            workflow_run_attempt=str(workflow["run_attempt"]),
        )
        platform_qualification.verify_artifact(args)
        record_path = artifact_root / platform_qualification.RECORD_NAME
        record_bytes = _snapshot(record_path, f"{platform_id} qualification record")
        record = json.loads(
            record_bytes.decode("utf-8"),
            object_pairs_hook=lambda pairs, label=(f"{platform_id} qualification record"): (
                _reject_duplicate_pairs(pairs, label)
            ),
        )
        if record_bytes != platform_qualification.canonical_json_bytes(record):
            raise ValueError("platform qualification record is not canonical")
        record_candidate = record.get("candidate")
        record_workflow = record.get("workflow")
        record_platform = record.get("platform")
        if (
            type(record_candidate) is not dict
            or record_candidate.get("run_id") != candidate["run_id"]
            or record_candidate.get("run_attempt") != candidate["run_attempt"]
            or record_candidate.get("source_sha") != candidate["source_sha"]
            or record_candidate.get("manifest_sha256") != candidate["manifest_sha256"]
            or record_candidate.get("oci_manifest_digest")
            != candidate["oci_manifest_digest"]
            or record_workflow
            != {
                "repository": project["repository"],
                "run_attempt": workflow["run_attempt"],
                "run_id": workflow["run_id"],
                "source_ref": project["source_ref"],
                "source_sha": project["source_sha"],
            }
            or type(record_platform) is not dict
            or record_platform.get("platform_id") != platform_id
        ):
            raise ValueError("verified platform record identity drift")
        post_state_path = artifact_root / "metadata" / "post-state.json"
        post_state_bytes = _snapshot(post_state_path, f"{platform_id} post-clean state")
        if post_state_bytes != empty_state_bytes:
            raise ValueError(
                "verified platform artifact does not retain empty post-state"
            )
        readback_sha256 = verify_platform_observation(
            observations_root / "readback" / platform_id,
            identity,
            role="readback",
            scope=platform_id,
        )
        rows.append(
            {
                "artifact": _artifact_from_identity(
                    identity, role="qualification", scope=platform_id
                ),
                "capture_sha256": record["capture_sha256"],
                "engine": record_platform["engine"],
                "evidence": record["evidence"],
                "platform_id": platform_id,
                "post_clean": {
                    "sha256": _sha256(post_state_bytes),
                    "status": "EMPTY",
                },
                "readback": {
                    "artifact": _artifact_from_identity(
                        identity, role="readback", scope=platform_id
                    ),
                    "observation_sha256": readback_sha256,
                },
                "record_sha256": _sha256(record_bytes),
                "runner": record_platform["runner"],
            }
        )
    return _validate_platform_consumption(
        {
            "candidate_binding": {
                "artifact": _artifact_from_identity(
                    identity, role="candidate-binding", scope="candidate"
                ),
                "observation_sha256": candidate_binding_sha256,
            },
            "identity": identity,
            "kind": PLATFORM_CONSUMPTION_KIND,
            "platforms": rows,
            "schema_version": 1,
            "status": platform_qualification.STATUS,
        }
    )


def build_publication_plan(
    *,
    attestation_path: Path,
    candidate_dir: Path,
    remote_state_path: Path,
    marker_identity_path: Path,
    platform_consumption_path: Path,
    release_pages_path: Path,
    ghcr_versions_path: Path,
    repository: str,
) -> tuple[dict, str]:
    """Build a read-only exact-byte plan; never grant mutation authority."""

    if not SLUG.fullmatch(repository):
        raise ValueError("publication repository is malformed")
    attestation = _load_json(attestation_path, "tag-promotion qualification index")
    assets = _attestation_assets(attestation, candidate_dir)
    attestation_bytes = _snapshot(attestation_path, "tag-promotion attestation")
    supplemental_assets = [
        {
            "name": "tag-promotion-attestation.json",
            "sha256": _sha256(attestation_bytes),
            "size": len(attestation_bytes),
        }
    ]
    release_assets = sorted(assets + supplemental_assets, key=lambda item: item["name"])
    candidate = attestation.get("candidate")
    external = attestation.get("external_authorization")
    authorization = external.get("authorization") if type(external) is dict else None
    tag = attestation.get("tag")
    oci = attestation.get("oci")
    if not all(type(item) is dict for item in (candidate, authorization, tag, oci)):
        raise ValueError("tag-promotion publication identity is incomplete")
    version = candidate.get("version")
    source_sha = candidate.get("source_sha")
    authorization_id = authorization.get("id")
    tag_oid = tag.get("object_sha")
    manifest_digest = oci.get("manifest_sha256")
    if (
        type(version) is not str
        or not re.fullmatch(r"[0-9A-Za-z.-]+", version)
        or type(source_sha) is not str
        or not SHA.fullmatch(source_sha)
        or type(authorization_id) is not str
        or not AUTHORIZATION_ID.fullmatch(authorization_id)
        or type(tag_oid) is not str
        or not SHA.fullmatch(tag_oid)
        or type(manifest_digest) is not str
        or not SHA256.fullmatch(manifest_digest)
    ):
        raise ValueError("tag-promotion publication identity is malformed")
    platform_consumption_bytes = _snapshot(
        platform_consumption_path, "platform qualification consumption"
    )
    platform_consumption = _validate_platform_consumption(
        json.loads(
            platform_consumption_bytes.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_pairs(
                pairs, "platform qualification consumption"
            ),
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(
                    f"platform qualification consumption contains non-finite JSON value {item}"
                )
            ),
        )
    )
    if platform_consumption_bytes != canonical_bytes(platform_consumption):
        raise ValueError("platform qualification consumption is not canonical JSON")
    platform_candidate = platform_consumption["identity"]["candidate"]
    external_candidate = external.get("candidate") if type(external) is dict else None
    if (
        platform_candidate["source_sha"] != source_sha
        or platform_candidate["manifest_sha256"] != candidate.get("manifest_sha256")
        or platform_candidate["oci_manifest_digest"] != manifest_digest
        or type(external_candidate) is not dict
        or platform_candidate["source_sha"] != external_candidate.get("commit")
        or platform_candidate["manifest_sha256"]
        != external_candidate.get("manifest_sha256")
        or platform_candidate["oci_manifest_digest"]
        != external_candidate.get("oci_manifest_digest")
        or platform_candidate["run_id"] != external_candidate.get("run_id")
        or platform_candidate["run_attempt"] != external_candidate.get("run_attempt")
    ):
        raise ValueError("platform consumption differs from authorized candidate")
    tag_name = f"v{version}"
    version_ref = f"refs/tags/{tag_name}"
    marker_ref = f"refs/tags/tomorrowci-authorization/{authorization_id}"
    if (
        tag.get("name") != tag_name
        or tag.get("internal_name") != tag_name
        or tag.get("peeled_commit") != source_sha
    ):
        raise ValueError("annotated version tag does not bind candidate identity")
    marker = _load_json(marker_identity_path, "authorization marker identity")
    marker_oid = marker.get("object_sha")
    if (
        type(marker_oid) is not str
        or not SHA.fullmatch(marker_oid)
        or marker.get("name") != f"tomorrowci-authorization/{authorization_id}"
        or marker.get("internal_name") != marker.get("name")
        or marker.get("peeled_commit") != source_sha
    ):
        raise ValueError("authorization marker does not bind candidate identity")
    remote = _load_json(remote_state_path, "promotion remote state")
    expected_refs = {marker_ref: marker_oid, version_ref: tag_oid}
    if (
        remote.get("kind") != KIND
        or remote.get("schema_version") != 1
        or remote.get("status") != DISABLED_STATUS
        or remote.get("state")
        not in {"READY_FOR_ATOMIC_CREATE_ONLY", "IDEMPOTENT_EXACT_PAIR"}
        or remote.get("refs")
        != {key: expected_refs[key] for key in sorted(expected_refs)}
    ):
        raise ValueError(
            "promotion remote ref state disagrees with exact annotated refs"
        )
    owner = repository.split("/", 1)[0].lower()
    oci_repository = f"ghcr.io/{owner}/tomorrowci"
    body = release_body(attestation, oci_repository=oci_repository)
    release = inspect_release_state(
        _page_items(release_pages_path, "GitHub Releases API pages"),
        tag_name=tag_name,
        target_commitish=source_sha,
        release_name=f"TomorrowCI {tag_name}",
        body=body,
        expected_assets=release_assets,
    )
    ghcr = inspect_ghcr_state(
        _page_items(ghcr_versions_path, "GHCR package-version API pages"),
        image_tag=tag_name,
        manifest_digest=manifest_digest,
    )
    plan = {
        "candidate": {
            "assets": assets,
            "source_sha": source_sha,
            "version": version,
        },
        "ghcr": {
            **ghcr,
            "repository": oci_repository,
            "source_archive": "tomorrowci-oci-linux-amd64.tar",
            "source_reference": f"v{version}-{source_sha}",
            "tool": ORAS_TOOL,
        },
        "kind": PUBLICATION_KIND,
        "mutation": {
            "plan_is_standalone_authority": False,
            "protected_roll_forward": True,
        },
        "platform_qualification": platform_consumption,
        "refs": {
            "atomic": True,
            "force": False,
            "identity": {key: expected_refs[key] for key in sorted(expected_refs)},
            "state": remote["state"],
        },
        "release": {
            **release,
            "assets": release_assets,
            "draft": True,
            "name": f"TomorrowCI {tag_name}",
            "prerelease": True,
            "tag_name": tag_name,
            "target_commitish": source_sha,
        },
        "schema_version": 1,
        "status": DISABLED_STATUS,
    }
    return plan, body


def _safe_extract_exact_zip(
    archive: Path,
    destination: Path,
    *,
    expected_files: set[str],
    label: str,
    max_uncompressed_bytes: int = 64 * 1024 * 1024,
) -> None:
    destination = destination.absolute()
    if destination.exists():
        raise ValueError(f"{label} extraction destination already exists")
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        names = [_safe_zip_member_name(entry, label) for entry in entries]
        if len(names) != len(set(names)) or set(names) != expected_files:
            raise ValueError(f"{label} bundle inventory mismatch")
        if sum(entry.file_size for entry in entries) > max_uncompressed_bytes:
            raise ValueError(f"{label} bundle exceeds size limit")
        for entry, name in zip(entries, names, strict=True):
            mode = entry.external_attr >> 16
            if (
                entry.is_dir()
                or entry.flag_bits & 0x1
                or Path(name).name != name
                or name in {".", ".."}
                or entry.file_size <= 0
                or (mode and not stat.S_ISREG(mode))
            ):
                raise ValueError(f"unsafe {label} bundle entry: {name!r}")
            data = package.read(entry)
            if len(data) != entry.file_size:
                raise ValueError(f"{label} entry size drift: {name}")
            with (destination / name).open("xb") as handle:
                handle.write(data)


def _safe_zip_member_name(entry: zipfile.ZipInfo, label: str) -> str:
    """Return an unmodified ZIP member name without hidden control aliases."""

    raw_name = entry.orig_filename
    name = entry.filename
    if (
        type(raw_name) is not str
        or type(name) is not str
        or raw_name != name
        or any(unicodedata.category(character) == "Cc" for character in raw_name)
        or any(unicodedata.category(character) == "Cc" for character in name)
    ):
        raise ValueError(f"unsafe {label} ZIP entry name: {raw_name!r}")
    return name


def safe_extract_platform_artifact(archive: Path, destination: Path) -> None:
    """Extract one digest-verified recursive platform artifact without aliases."""

    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("platform artifact extraction destination already exists")
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        if not entries or len(entries) > 50_000:
            raise ValueError("platform artifact ZIP file count is invalid")
        total = sum(entry.file_size for entry in entries)
        if total > 512 * 1024 * 1024:
            raise ValueError("platform artifact ZIP exceeds size limit")
        names: set[str] = set()
        casefolded: set[str] = set()
        for entry in entries:
            name = _safe_zip_member_name(entry, "platform artifact")
            relative = PurePosixPath(name)
            mode = entry.external_attr >> 16
            folded = name.casefold()
            if (
                entry.is_dir()
                or entry.flag_bits & 0x1
                or not name
                or "\\" in name
                or relative.is_absolute()
                or str(relative) != name
                or any(part in {"", ".", ".."} for part in relative.parts)
                or any(":" in part for part in relative.parts)
                or name in names
                or folded in casefolded
                or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
            ):
                raise ValueError(f"unsafe platform artifact ZIP entry: {name!r}")
            names.add(name)
            casefolded.add(folded)
            data = package.read(entry)
            if len(data) != entry.file_size:
                raise ValueError(f"platform artifact entry size drift: {name}")
            output = destination.joinpath(*relative.parts)
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with output.open("xb") as handle:
                handle.write(data)


def safe_extract_platform_observation(
    archive: Path, destination: Path, *, role: str
) -> None:
    expected = {
        "candidate-binding": {"candidate-binding-pass.txt"},
        "readback": {"readback-pass.txt"},
    }.get(role)
    if expected is None:
        raise ValueError("unknown platform observation role")
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=expected,
        label=f"platform {role} observation",
    )


def safe_extract_authorization(archive: Path, destination: Path) -> None:
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=AUTHORIZATION_FILES,
        label="authorization",
    )


def safe_extract_prepared_state(archive: Path, destination: Path) -> None:
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=PREPARED_STATE_FILES,
        label="prepared state",
    )


def safe_extract_candidate(archive: Path, destination: Path, *, version: str) -> None:
    """Extract only the exact frozen candidate inventory from verified raw bytes.

    The Actions artifact downloader is intentionally not the trust boundary for
    promotion.  Callers must first authenticate the API ZIP's size and digest,
    then use this strict extraction before candidate-manifest verification.
    """

    expected_files = {
        *candidate_manifest.payload_names(version),
        candidate_manifest.CHECKSUMS_NAME,
        candidate_manifest.MANIFEST_NAME,
    }
    _safe_extract_exact_zip(
        archive,
        destination,
        expected_files=expected_files,
        label="candidate",
        max_uncompressed_bytes=2 * 1024 * 1024 * 1024,
    )


def remote_state(
    text: str,
    *,
    version_ref: str,
    version_oid: str,
    marker_ref: str,
    marker_oid: str,
) -> dict:
    expected = {version_ref: version_oid, marker_ref: marker_oid}
    if (
        not REF.fullmatch(version_ref)
        or not REF.fullmatch(marker_ref)
        or version_ref == marker_ref
        or not SHA.fullmatch(version_oid)
        or not SHA.fullmatch(marker_oid)
    ):
        raise ValueError("expected promotion ref identity is malformed")
    observed: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if (
            len(fields) != 2
            or not SHA.fullmatch(fields[0])
            or fields[1] not in expected
        ):
            raise ValueError("remote ref observation contains an unexpected entry")
        if fields[1] in observed:
            raise ValueError("remote ref observation contains a duplicate ref")
        observed[fields[1]] = fields[0]
    if not observed:
        state = "READY_FOR_ATOMIC_CREATE_ONLY"
    elif observed == expected:
        state = "IDEMPOTENT_EXACT_PAIR"
    else:
        raise ValueError("remote tag/authorization marker is partial or mismatched")
    return {
        "kind": KIND,
        "refs": {key: expected[key] for key in sorted(expected)},
        "schema_version": 1,
        "state": state,
        "status": DISABLED_STATUS,
    }


def inspect_authorization_marker(
    *,
    git_repo: Path,
    marker_ref: str,
    candidate_source_sha: str,
    authorization_id: str,
) -> dict:
    """Require a direct annotated marker binding one authorization to one commit."""

    if not SHA.fullmatch(candidate_source_sha):
        raise ValueError("candidate source SHA is malformed")
    if not AUTHORIZATION_ID.fullmatch(authorization_id):
        raise ValueError("authorization ID is malformed")
    marker_name = f"tomorrowci-authorization/{authorization_id}"
    expected_ref = f"refs/tags/{marker_name}"
    if marker_ref != expected_ref:
        raise ValueError("authorization marker ref does not match its exact ID")
    identity = tag_promotion_attestation._annotated_tag_ref_identity(
        git_repo, marker_name
    )
    if (
        identity.get("target_type") != "commit"
        or identity.get("target_sha") != candidate_source_sha
        or identity.get("peeled_commit") != candidate_source_sha
        or identity.get("internal_name") != marker_name
        or identity.get("name") != marker_name
    ):
        raise ValueError(
            "authorization marker annotated tag does not bind the exact candidate commit"
        )
    return identity


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def refuse_unconditional_ghcr_tag_write() -> None:
    raise ValueError(
        "GHCR publication is disabled: the registry tag PUT used by ORAS has no "
        "proven create-only/If-None-Match primitive, so a concurrent tag cannot be "
        "updated without clobber risk"
    )


def refuse_unconditional_release_publish() -> None:
    raise ValueError(
        "GitHub Release publication is disabled: the documented release PATCH "
        "endpoint has no conditional If-Match primitive, so a validated draft "
        "cannot be published without a final concurrent-update window"
    )


def verify_platform_plan_binding(plan_path: Path, consumption_path: Path) -> dict:
    plan = _load_json(plan_path, "exact-byte publication plan")
    data = _snapshot(consumption_path, "platform qualification consumption")
    consumption = _validate_platform_consumption(
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_pairs(
                pairs, "platform qualification consumption"
            ),
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(
                    f"platform qualification consumption contains non-finite JSON value {item}"
                )
            ),
        )
    )
    if data != canonical_bytes(consumption):
        raise ValueError("platform qualification consumption is not canonical JSON")
    if (
        plan.get("kind") != PUBLICATION_KIND
        or plan.get("status") != DISABLED_STATUS
        or plan.get("platform_qualification") != consumption
    ):
        raise ValueError("publication plan platform consumption binding mismatch")
    return consumption


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    dispatch = commands.add_parser("parse-dispatch-run-coordinates")
    dispatch.add_argument("--value", required=True)
    ci = commands.add_parser("inspect-ci-api")
    ci.add_argument("--metadata", type=Path, required=True)
    ci.add_argument("--repository", required=True)
    ci.add_argument("--source-sha", required=True)
    ci.add_argument("--run-id", required=True)
    ci.add_argument("--run-attempt", required=True)
    repository_head = commands.add_parser("inspect-repository-head")
    repository_head.add_argument("--repository-metadata", type=Path, required=True)
    repository_head.add_argument("--branch-metadata", type=Path, required=True)
    repository_head.add_argument("--repository", required=True)
    repository_head.add_argument("--source-sha", required=True)
    workflow_run = commands.add_parser("inspect-promotion-run")
    workflow_run.add_argument("--metadata", type=Path, required=True)
    workflow_run.add_argument("--repository", required=True)
    workflow_run.add_argument("--source-sha", required=True)
    workflow_run.add_argument("--run-id", required=True)
    workflow_run.add_argument("--run-attempt", required=True)
    artifact = commands.add_parser("inspect-authorization-artifact")
    artifact.add_argument("--metadata", type=Path, required=True)
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--artifact-sha256", required=True)
    platform_api = commands.add_parser("inspect-platform-api")
    platform_api.add_argument("--run-metadata", type=Path, required=True)
    platform_api.add_argument("--artifact-metadata", type=Path, required=True)
    platform_api.add_argument("--repository", required=True)
    platform_api.add_argument("--source-sha", required=True)
    platform_api.add_argument("--run-id", required=True)
    platform_api.add_argument("--run-attempt", required=True)
    platform_api.add_argument("--candidate-run-id", required=True)
    platform_api.add_argument("--candidate-run-attempt", required=True)
    platform_api.add_argument("--candidate-manifest-sha256", required=True)
    platform_api.add_argument("--oci-manifest-digest", required=True)
    platform_api.add_argument("--expected-identity-sha256")
    platform_api.add_argument("--output", type=Path, required=True)
    environment = commands.add_parser("inspect-release-environment")
    environment.add_argument("--metadata", type=Path, required=True)
    approval = commands.add_parser("inspect-approval-history")
    approval.add_argument("--approvals", type=Path, required=True)
    approval.add_argument("--environment", type=Path, required=True)
    approval.add_argument("--run-metadata", type=Path, required=True)
    extract = commands.add_parser("extract-authorization")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    state_extract = commands.add_parser("extract-prepared-state")
    state_extract.add_argument("--archive", type=Path, required=True)
    state_extract.add_argument("--destination", type=Path, required=True)
    candidate_extract = commands.add_parser("extract-candidate")
    candidate_extract.add_argument("--archive", type=Path, required=True)
    candidate_extract.add_argument("--destination", type=Path, required=True)
    candidate_extract.add_argument("--version", required=True)
    platform_extract = commands.add_parser("extract-platform-artifact")
    platform_extract.add_argument("--archive", type=Path, required=True)
    platform_extract.add_argument("--destination", type=Path, required=True)
    platform_observation_extract = commands.add_parser("extract-platform-observation")
    platform_observation_extract.add_argument("--archive", type=Path, required=True)
    platform_observation_extract.add_argument("--destination", type=Path, required=True)
    platform_observation_extract.add_argument(
        "--role", choices=("candidate-binding", "readback"), required=True
    )
    platform_consumption = commands.add_parser("verify-platform-consumption")
    platform_consumption.add_argument("--identity", type=Path, required=True)
    platform_consumption.add_argument("--artifacts-root", type=Path, required=True)
    platform_consumption.add_argument("--observations-root", type=Path, required=True)
    platform_consumption.add_argument("--candidate-dist", type=Path, required=True)
    platform_consumption.add_argument("--fixture-source", type=Path, required=True)
    platform_consumption.add_argument("--output", type=Path, required=True)
    platform_plan = commands.add_parser("verify-platform-plan-binding")
    platform_plan.add_argument("--plan", type=Path, required=True)
    platform_plan.add_argument("--consumption", type=Path, required=True)
    refs = commands.add_parser("inspect-remote-refs")
    refs.add_argument("--observation", type=Path, required=True)
    refs.add_argument("--version-ref", required=True)
    refs.add_argument("--version-oid", required=True)
    refs.add_argument("--marker-ref", required=True)
    refs.add_argument("--marker-oid", required=True)
    refs.add_argument("--output", type=Path, required=True)
    marker = commands.add_parser("inspect-authorization-marker")
    marker.add_argument("--git-repo", type=Path, required=True)
    marker.add_argument("--marker-ref", required=True)
    marker.add_argument("--candidate-source-sha", required=True)
    marker.add_argument("--authorization-id", required=True)
    oci = commands.add_parser("inspect-oci-manifest")
    oci.add_argument("--provenance", type=Path, required=True)
    oci.add_argument("--expected-digest", required=True)
    packages = commands.add_parser("inspect-package-pages")
    packages.add_argument("--pages", type=Path, required=True)
    packages.add_argument("--package-name", required=True)
    packages.add_argument("--owner", required=True)
    immutable = commands.add_parser("inspect-immutable-release-setting")
    immutable.add_argument("--metadata", type=Path, required=True)
    ghcr = commands.add_parser("inspect-ghcr-pages")
    ghcr.add_argument("--pages", type=Path, required=True)
    ghcr.add_argument("--image-tag", required=True)
    ghcr.add_argument("--manifest-digest", required=True)
    ghcr.add_argument("--required-state")
    plan = commands.add_parser("build-publication-plan")
    plan.add_argument("--attestation", type=Path, required=True)
    plan.add_argument("--candidate-dir", type=Path, required=True)
    plan.add_argument("--remote-state", type=Path, required=True)
    plan.add_argument("--marker-identity", type=Path, required=True)
    plan.add_argument("--platform-consumption", type=Path, required=True)
    plan.add_argument("--release-pages", type=Path, required=True)
    plan.add_argument("--ghcr-versions", type=Path, required=True)
    plan.add_argument("--repository", required=True)
    plan.add_argument("--release-body-output", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    readback = commands.add_parser("verify-public-assets")
    readback.add_argument("--plan", type=Path, required=True)
    readback.add_argument("--directory", type=Path, required=True)
    candidate_readback = commands.add_parser("verify-candidate-assets")
    candidate_readback.add_argument("--plan", type=Path, required=True)
    candidate_readback.add_argument("--directory", type=Path, required=True)
    public_oci = commands.add_parser("inspect-public-oci-descriptor")
    public_oci.add_argument("--descriptor", type=Path, required=True)
    public_oci.add_argument("--expected-digest", required=True)
    etag = commands.add_parser("inspect-http-etag")
    etag.add_argument("--headers", type=Path, required=True)
    doctor = commands.add_parser("inspect-doctor-output")
    doctor.add_argument("--output", type=Path, required=True)
    doctor.add_argument("--expected-version", required=True)
    commands.add_parser("assert-ghcr-nonclobber-write")
    commands.add_parser("assert-release-publish-nonclobber")
    args = parser.parse_args(argv)
    try:
        if args.command == "parse-dispatch-run-coordinates":
            value = parse_dispatch_run_coordinates(args.value)
            for field in RUN_COORDINATE_FIELDS:
                print(f"{field}={value[field]}")
        elif args.command == "inspect-ci-api":
            value = inspect_ci_run(
                _load_json(args.metadata, "CI run metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-repository-head":
            value = inspect_repository_head(
                _load_json(args.repository_metadata, "repository metadata"),
                _load_json(args.branch_metadata, "default branch metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-promotion-run":
            value = inspect_promotion_workflow_run(
                _load_json(args.metadata, "promotion run metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-authorization-artifact":
            value = inspect_artifact(
                _load_json(args.metadata, "authorization artifact metadata"),
                artifact_id=args.artifact_id,
                artifact_sha256=args.artifact_sha256,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-platform-api":
            value = inspect_platform_api(
                _load_json(args.run_metadata, "platform workflow run metadata"),
                _load_json(args.artifact_metadata, "platform artifact API metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                candidate_run_id=args.candidate_run_id,
                candidate_run_attempt=args.candidate_run_attempt,
                candidate_manifest_sha256=args.candidate_manifest_sha256,
                oci_manifest_digest=args.oci_manifest_digest,
                expected_identity_sha256=args.expected_identity_sha256,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            print(
                "platform qualification API identity: PASS: "
                f"{_sha256(canonical_bytes(value))}"
            )
        elif args.command == "inspect-release-environment":
            value = inspect_release_environment(
                _load_json(args.metadata, "release environment metadata")
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-approval-history":
            value = inspect_approval_history(
                _load_json_array(args.approvals, "approval history"),
                environment_metadata=_load_json(
                    args.environment, "release environment metadata"
                ),
                run_metadata=_load_json(args.run_metadata, "promotion run metadata"),
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "extract-authorization":
            safe_extract_authorization(args.archive, args.destination)
            print("authorization bundle: PASS")
        elif args.command == "extract-prepared-state":
            safe_extract_prepared_state(args.archive, args.destination)
            print("prepared state bundle: PASS")
        elif args.command == "extract-candidate":
            safe_extract_candidate(args.archive, args.destination, version=args.version)
            print("candidate bundle: PASS")
        elif args.command == "extract-platform-artifact":
            safe_extract_platform_artifact(args.archive, args.destination)
            print("platform qualification artifact: strict extraction PASS")
        elif args.command == "extract-platform-observation":
            safe_extract_platform_observation(
                args.archive, args.destination, role=args.role
            )
            print(f"platform {args.role} observation: strict extraction PASS")
        elif args.command == "verify-platform-consumption":
            value = verify_platform_consumption(
                identity_path=args.identity,
                artifacts_root=args.artifacts_root,
                observations_root=args.observations_root,
                candidate_dist=args.candidate_dist,
                fixture_source=args.fixture_source,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            print("platform qualification consumption: PASS")
        elif args.command == "verify-platform-plan-binding":
            verify_platform_plan_binding(args.plan, args.consumption)
            print("publication plan platform consumption: PASS")
        elif args.command == "inspect-remote-refs":
            value = remote_state(
                args.observation.read_text(encoding="utf-8"),
                version_ref=args.version_ref,
                version_oid=args.version_oid,
                marker_ref=args.marker_ref,
                marker_oid=args.marker_oid,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            print(f"promotion remote state: PASS: {value['state']}")
        elif args.command == "inspect-authorization-marker":
            value = inspect_authorization_marker(
                git_repo=args.git_repo,
                marker_ref=args.marker_ref,
                candidate_source_sha=args.candidate_source_sha,
                authorization_id=args.authorization_id,
            )
            sys.stdout.buffer.write(canonical_bytes(value))
        elif args.command == "inspect-oci-manifest":
            digest = inspect_oci_manifest_digest(args.provenance, args.expected_digest)
            print(f"OCI authoritative manifest digest: PASS: {digest}")
        elif args.command == "inspect-package-pages":
            print(
                inspect_package_pages(
                    args.pages, package_name=args.package_name, owner=args.owner
                )
            )
        elif args.command == "inspect-immutable-release-setting":
            inspect_immutable_release_setting(
                _load_json(args.metadata, "immutable-release setting")
            )
            print("repository immutable releases: PASS")
        elif args.command == "inspect-ghcr-pages":
            value = inspect_ghcr_state(
                _page_items(args.pages, "GHCR package-version API pages"),
                image_tag=args.image_tag,
                manifest_digest=args.manifest_digest,
            )
            if (
                args.required_state is not None
                and value["state"] != args.required_state
            ):
                raise ValueError("GHCR state does not equal the required exact state")
            print(json.dumps(value, sort_keys=True))
        elif args.command == "build-publication-plan":
            value, body = build_publication_plan(
                attestation_path=args.attestation,
                candidate_dir=args.candidate_dir,
                remote_state_path=args.remote_state,
                marker_identity_path=args.marker_identity,
                platform_consumption_path=args.platform_consumption,
                release_pages_path=args.release_pages,
                ghcr_versions_path=args.ghcr_versions,
                repository=args.repository,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            with args.release_body_output.open(
                "x", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write(body)
            print("exact-byte publication plan: PASS: protected roll-forward only")
        elif args.command in {"verify-public-assets", "verify-candidate-assets"}:
            value = _load_json(args.plan, "exact-byte publication plan")
            candidate = value.get("candidate")
            release = value.get("release")
            if (
                value.get("kind") != PUBLICATION_KIND
                or value.get("status") != DISABLED_STATUS
                or type(candidate) is not dict
                or type(candidate.get("assets")) is not list
                or type(release) is not dict
                or type(release.get("assets")) is not list
            ):
                raise ValueError("exact-byte publication plan identity mismatch")
            expected = (
                release["assets"]
                if args.command == "verify-public-assets"
                else candidate["assets"]
            )
            inspect_public_asset_readback(args.directory, expected)
            print(f"{args.command}: PASS")
        elif args.command == "inspect-public-oci-descriptor":
            value = inspect_public_oci_descriptor(args.descriptor, args.expected_digest)
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-http-etag":
            print(inspect_http_etag(args.headers))
        elif args.command == "inspect-doctor-output":
            value = inspect_doctor_output(
                args.output, expected_version=args.expected_version
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "assert-ghcr-nonclobber-write":
            refuse_unconditional_ghcr_tag_write()
        elif args.command == "assert-release-publish-nonclobber":
            refuse_unconditional_release_publish()
        else:
            raise ValueError("unhandled promotion-preflight command")
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"promotion-preflight: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
