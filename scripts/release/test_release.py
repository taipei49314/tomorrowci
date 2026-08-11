from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("release.py")
SPEC = importlib.util.spec_from_file_location("tomorrowci_release", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseHelpersTest(unittest.TestCase):
    VERSION = "0.2.0"
    SOURCE_SHA = "1" * 40
    CANDIDATE_ARTIFACT_DIGEST = "sha256:" + "6" * 64
    QUALIFICATION_ARTIFACT_DIGEST = "sha256:" + "7" * 64

    TARGETS = {
        "python": (
            "https://github.com/jmespath/jmespath.py",
            "2812594e69d43098ef60f81f4efc404c071b0418",
            "docs/qualification/external/python-jmespath.yml",
        ),
        "node": (
            "https://github.com/tj/commander.js",
            "ba6d13ddb4243e5913367734f8c159089ffe7834",
            "docs/qualification/external/node-commander.yml",
        ),
        "rust": (
            "https://github.com/sharkdp/fd",
            "d38148f0aabdd073b4080cde770f679f3197b920",
            "docs/qualification/external/rust-fd.yml",
        ),
    }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_package_inputs(self) -> tuple[Path, list[Path]]:
        binary = self.root / "tomorrowci"
        binary.write_bytes(b"binary\x00payload")
        documents: list[Path] = []
        for name in release.DOCUMENTS:
            path = self.root / name
            path.write_text(f"{name}\n", encoding="utf-8")
            documents.append(path)
        return binary, documents

    def package(self, archive_format: str, output: Path) -> None:
        binary, documents = self.make_package_inputs()
        release.package_archive(
            argparse.Namespace(
                format=archive_format,
                binary=str(binary),
                output=str(output),
                root="tomorrowci-0.2.0-test-target",
                document=[str(path) for path in documents],
            )
        )

    def test_tar_and_zip_are_deterministic_with_one_versioned_root(self) -> None:
        for archive_format, suffix in (("tar.gz", ".tar.gz"), ("zip", ".zip")):
            first = self.root / f"first{suffix}"
            second = self.root / f"second{suffix}"
            self.package(archive_format, first)
            os.utime(self.root / "README.md", (2_000_000_000, 2_000_000_000))
            self.package(archive_format, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            release.verify_archive(
                argparse.Namespace(
                    archive=str(first),
                    format=archive_format,
                    root="tomorrowci-0.2.0-test-target",
                    binary_name="tomorrowci",
                )
            )
            destination = self.root / f"extract-{archive_format.replace('.', '-')}"
            release.extract_archive(
                argparse.Namespace(
                    archive=str(first),
                    format=archive_format,
                    root="tomorrowci-0.2.0-test-target",
                    binary_name="tomorrowci",
                    destination=str(destination),
                )
            )
            extracted = destination / "tomorrowci-0.2.0-test-target" / "tomorrowci"
            self.assertEqual(extracted.read_bytes(), b"binary\x00payload")

    def make_lock_and_sbom(self) -> tuple[Path, dict[str, object]]:
        lock = self.root / "Cargo.lock"
        lock.write_text(
            'version = 3\n\n[[package]]\nname = "tomorrowci"\nversion = "0.2.0"\n'
            '\n[[package]]\nname = "tomorrowci-adapter-example"\nversion = "0.2.0"\n'
            '\n[[package]]\nname = "serde"\nversion = "1.0.0"\n',
            encoding="utf-8",
        )
        sbom = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": "1970-01-01T00:00:00.000000000Z",
                "component": {
                    "type": "application",
                    "bom-ref": "pkg:cargo/tomorrowci-workspace@0.2.0",
                    "name": "tomorrowci-workspace",
                    "version": "0.2.0",
                },
            },
            "components": [
                {
                    "type": "application",
                    "bom-ref": "pkg:cargo/tomorrowci@0.2.0",
                    "name": "tomorrowci",
                    "version": "0.2.0",
                },
                {
                    "type": "library",
                    "bom-ref": "pkg:cargo/tomorrowci-adapter-example@0.2.0",
                    "name": "tomorrowci-adapter-example",
                    "version": "0.2.0",
                },
                {
                    "type": "library",
                    "bom-ref": "pkg:cargo/serde@1.0.0",
                    "name": "serde",
                    "version": "1.0.0",
                },
            ],
            "dependencies": [
                {
                    "ref": "pkg:cargo/tomorrowci-workspace@0.2.0",
                    "dependsOn": [
                        "pkg:cargo/tomorrowci@0.2.0",
                        "pkg:cargo/tomorrowci-adapter-example@0.2.0",
                    ],
                }
            ],
        }
        return lock, sbom

    def qualification_requirements(self) -> dict[str, object]:
        return {
            "project_operated_public_targets_required": 3,
            "ecosystems": ["python", "node", "rust"],
            "independent_results_required": 1,
            "required_flow": "scan -> verify -> replay",
            "required_identity": [
                "candidate source SHA",
                "candidate artifact digest",
                "target repository and commit",
                "engine and image digests",
                "evidence bundle digest",
                "auditor or adopter identity",
            ],
        }

    def write_frozen_external_contract(self, directory: Path) -> dict[str, str]:
        (directory / release.EXTERNAL_PROTOCOL_SNAPSHOT).write_text(
            "# Frozen external protocol\n", encoding="utf-8"
        )
        config_digests: dict[str, str] = {}
        targets: list[dict[str, object]] = []
        for ecosystem, (repository, source_sha, config_path) in self.TARGETS.items():
            snapshot_name = release.EXTERNAL_CONFIG_SNAPSHOTS[ecosystem]
            snapshot = directory / snapshot_name
            snapshot.write_text(
                f"version: 1\nproject:\n  ecosystem: {ecosystem}\n",
                encoding="utf-8",
            )
            config_digest = release.sha256_file(snapshot)
            config_digests[ecosystem] = config_digest
            targets.append(
                {
                    "ecosystem": ecosystem,
                    "repository": repository,
                    "source_sha": source_sha,
                    "config_path": config_path,
                    "config_sha256": config_digest,
                    "status": "NOT_RUN",
                    "workflow_url": None,
                    "evidence_sha256": None,
                }
            )
        frozen = {
            "schema_version": 1,
            "candidate_version": self.VERSION,
            "candidate_source_sha": None,
            "candidate_manifest_sha256": None,
            "status": "BLOCKED_EXTERNAL",
            "qualification_requirements": self.qualification_requirements(),
            "project_operated_targets": targets,
            "independent_results": [],
            "blocking_reason": "A genuinely independent public result is still required.",
        }
        release.write_json(directory / release.EXTERNAL_SNAPSHOT, frozen)
        return config_digests

    def make_payload(self) -> tuple[Path, Path, dict[str, str]]:
        directory = self.root / "candidate"
        directory.mkdir()
        for name in release.candidate_payload_names(self.VERSION):
            if name in {
                release.SBOM_NAME,
                release.EXTERNAL_SNAPSHOT,
                release.EXTERNAL_PROTOCOL_SNAPSHOT,
                release.CANDIDATE_RUN_BINDING_NAME,
                *release.EXTERNAL_CONFIG_SNAPSHOTS.values(),
            }:
                continue
            (directory / name).write_bytes(f"payload:{name}\n".encode())
        lock, sbom = self.make_lock_and_sbom()
        release.write_json(directory / release.SBOM_NAME, sbom)
        config_digests = self.write_frozen_external_contract(directory)
        release.create_run_binding(
            argparse.Namespace(
                output=str(directory / release.CANDIDATE_RUN_BINDING_NAME),
                mode="candidate",
                run_id="123",
                run_attempt="2",
                workflow_ref="owner/repo/.github/workflows/release.yml@refs/heads/master",
                candidate_run_id="",
                candidate_manifest_sha256="",
                qualification_index_sha256="",
            )
        )
        return directory, lock, config_digests

    def create_candidate(self, directory: Path, lock: Path) -> str:
        release.create_candidate(
            argparse.Namespace(
                directory=str(directory),
                lock=str(lock),
                version=self.VERSION,
                source_sha=self.SOURCE_SHA,
                repository="owner/repo",
                run_id="123",
                run_attempt="2",
                workflow_ref="owner/repo/.github/workflows/release.yml@refs/heads/master",
                rust_toolchain="1.97.1",
                sbom_tool_version="0.5.9",
                sbom_schema_commit="c320fc0f0b46873864927d9d5684eea7ba439728",
                jsonschema_version="4.25.1",
                source_date_epoch="0",
            )
        )
        return release.sha256_file(directory / release.MANIFEST_NAME)

    def result(
        self,
        ecosystem: str,
        manifest_digest: str,
        config_digest: str,
        independent: bool = False,
        replay_target_exit: int = 0,
    ) -> dict[str, object]:
        repository, source_sha, _ = self.TARGETS[ecosystem]
        run_owner = "external-auditor" if independent else "owner"
        run_repository = "independent-audit" if independent else "repo"
        release_tag = "tomorrowci-independent-qualification-001"
        evidence_name = (
            "tomorrowci-independent-evidence.zip"
            if independent
            else "tomorrowci-external-evidence"
        )
        record: dict[str, object] = {
            "candidate_artifact_digest": self.CANDIDATE_ARTIFACT_DIGEST,
            "candidate_manifest_sha256": manifest_digest,
            "config_sha256": config_digest,
            "ecosystem": ecosystem,
            "engine": "docker",
            "engine_version": "28.0.4",
            "evidence_artifact_name": evidence_name,
            "evidence_run_id": "external-run",
            "evidence_sha256": "5" * 64,
            "evidence_url": (
                f"https://github.com/{run_owner}/{run_repository}/releases/download/"
                f"{release_tag}/{evidence_name}"
                if independent
                else f"https://github.com/{run_owner}/{run_repository}/actions/runs/456/artifacts/789"
            ),
            "image_digests": [f"docker.io/library/{ecosystem}@sha256:{'4' * 64}"],
            "replay_exit_code": 0 if replay_target_exit == 0 else 3,
            "replay_expected_target_exit_code": replay_target_exit,
            "replay_outcome_class": (
                "PASS_REPRODUCED"
                if replay_target_exit == 0
                else "TARGET_FAILURE_REPRODUCED"
            ),
            "replay_scenario_id": "future",
            "repository": repository,
            "run_attempt": 1,
            "run_url": f"https://github.com/{run_owner}/{run_repository}/actions/runs/456",
            "scan_exit_code": 3,
            "source_sha": source_sha,
            "status": "PASS",
            "verify_exit_code": 0,
            "signer_workflow": (
                f"{run_owner}/{run_repository}/.github/workflows/external-qualification.yml"
                if independent
                else "owner/repo/.github/workflows/external-targets.yml"
            ),
            "workflow_source_sha": "8" * 40 if independent else self.SOURCE_SHA,
        }
        if independent:
            record["auditor_identity"] = "https://github.com/external-auditor"
            record["release_asset_id"] = 901
            record["release_id"] = 900
            record["release_tag"] = release_tag
            record["release_url"] = (
                f"https://github.com/{run_owner}/{run_repository}/releases/tag/{release_tag}"
            )
        subject = release.qualification_attestation_subject(record)
        subject_bytes = (
            json.dumps(subject, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        record["result_sha256"] = hashlib.sha256(subject_bytes).hexdigest()
        return record

    def seal_evidence_directory(self, directory: Path, kind: str) -> bytes:
        inventory_path = directory / "checksums.txt"
        if inventory_path.exists():
            inventory_path.unlink()
        lines = [
            f"# tomorrowci-evidence-checksums-v2 kind={kind} "
            "algorithm=sha256 scope=recursive sealed=true"
        ]
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            relative = path.relative_to(directory).as_posix()
            lines.append(f"{release.sha256_file(path)}  {relative}")
        inventory = ("\n".join(lines) + "\n").encode("utf-8")
        inventory_path.write_bytes(inventory)
        return inventory

    def write_receipt_rich_archive(
        self,
        archive_path: Path,
        record: dict[str, object],
        subject_bytes: bytes,
        bundle_bytes: bytes | None = None,
        *,
        include_bundle: bool = True,
        unsafe_member: bool = False,
        tamper_receipt_after_seal: bool = False,
    ) -> None:
        package = self.root / f"package-{archive_path.stem}"
        if package.exists():
            for path in sorted(package.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                else:
                    path.rmdir()
            package.rmdir()
        package.mkdir()
        (package / release.QUALIFICATION_RESULT_NAME).write_bytes(subject_bytes)
        run_id = str(record["evidence_run_id"])
        scenario_id = str(record["replay_scenario_id"])
        target_exit = int(record["replay_expected_target_exit_code"])
        run = package / "evidence" / "runs" / run_id
        scenario = run / "scenarios" / scenario_id
        attempt = scenario / "attempts" / "attempt-000001"
        attempt.mkdir(parents=True)
        release.write_json(attempt / "attempt.json", {"attempt_id": "original-attempt"})
        attempt_inventory = self.seal_evidence_directory(attempt, "replay-attempt")
        release.write_json(run / "run.json", {"run_id": run_id, "status": "COMPLETED"})
        release.write_json(run / "source-manifest.json", {"schema_version": 2})
        release.write_json(run / "config.normalized.json", {"schema_version": 1})
        release.write_json(scenario / "scenario.json", {"scenario_id": scenario_id})
        release.write_json(
            scenario / "replay-manifest-v2.json",
            {"schema_version": 2, "run_id": run_id, "scenario_id": scenario_id},
        )
        release.write_json(
            scenario / "result.json",
            {
                "scenario_id": scenario_id,
                "exit_code": target_exit,
                "signal": None,
                "timed_out": False,
                "blocked_reason": None,
            },
        )
        scenario_inventory = self.seal_evidence_directory(scenario, "scenario")
        run_inventory = self.seal_evidence_directory(run, "run")

        receipt_base = package / "evidence" / "replay-receipts" / run_id / scenario_id
        raw = package / "raw"
        raw.mkdir()
        receipt_ids: list[str] = []
        receipt_inventory_digests: list[str] = []
        original_attempt_sha = f"sha256:{release.sha256_file(attempt / 'attempt.json')}"
        for ordinal in (1, 2):
            receipt_id = f"receipt-{ordinal:04d}"
            receipt_ids.append(receipt_id)
            receipt = receipt_base / receipt_id
            origin = receipt / "origin"
            origin.mkdir(parents=True)
            origin_bindings = {
                "run.checksums.txt": run / "checksums.txt",
                "scenario.checksums.txt": scenario / "checksums.txt",
                "original-attempt.checksums.txt": attempt / "checksums.txt",
                "source-manifest.json": run / "source-manifest.json",
                "config.normalized.json": run / "config.normalized.json",
                "scenario.json": scenario / "scenario.json",
                "replay-manifest-v2.json": scenario / "replay-manifest-v2.json",
                "original-attempt.json": attempt / "attempt.json",
            }
            for name, source in origin_bindings.items():
                (origin / name).write_bytes(source.read_bytes())
            release.write_json(
                receipt / "public-replay-receipt.json",
                {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "original_run_inventory_sha256": hashlib.sha256(run_inventory).hexdigest(),
                    "original_scenario_inventory_sha256": hashlib.sha256(
                        scenario_inventory
                    ).hexdigest(),
                    "original_attempt_inventory_sha256": hashlib.sha256(
                        attempt_inventory
                    ).hexdigest(),
                    "original_attempt_path": (
                        f"scenarios/{scenario_id}/attempts/attempt-000001"
                    ),
                    "original_attempt_sha256": original_attempt_sha,
                    "equivalent_to_original": True,
                    "mismatches": [],
                },
            )
            receipt_inventory = self.seal_evidence_directory(receipt, "replay-attempt")
            inventory_digest = hashlib.sha256(receipt_inventory).hexdigest()
            receipt_inventory_digests.append(inventory_digest)
            logged = {
                "equivalent_to_original": True,
                "inventory_sha256": f"sha256:{inventory_digest}",
                "ordinal": ordinal,
                "path": f"/tmp/replay-receipts/{run_id}/{scenario_id}/{receipt_id}",
                "receipt_id": receipt_id,
            }
            (raw / f"replay-{ordinal}.log").write_bytes(
                (
                    "REPLAY_RECEIPT "
                    + json.dumps(logged, separators=(",", ":"))
                    + "\n"
                ).encode("utf-8")
            )
            (raw / f"replay-{ordinal}.exit-code").write_bytes(
                f"{record['replay_exit_code']}\n".encode("ascii")
            )
        if tamper_receipt_after_seal:
            first = receipt_base / receipt_ids[0] / "public-replay-receipt.json"
            value = release.load_json_object(first, "test receipt")
            value["mismatches"] = ["tampered-after-seal"]
            release.write_json(first, value)
        outcome = "Passed" if target_exit == 0 else "Failed"
        pair_line = (
            "PASS kind=replay-pair receipt_count=2 "
            f"run_id={run_id} scenario_id={scenario_id} "
            f"original_attempt_sha256={original_attempt_sha} outcome={outcome} "
            f"target_exit=Some({target_exit}) "
            f"receipt_ids={json.dumps(receipt_ids, separators=(',', ':'))} "
            "receipt_inventory_sha256="
            f"{json.dumps(receipt_inventory_digests, separators=(',', ':'))}\n"
        )
        (raw / "replay-pair.log").write_bytes(pair_line.encode("utf-8"))
        if bundle_bytes is not None and include_bundle:
            (package / release.QUALIFICATION_ATTESTATION_BUNDLE_NAME).write_bytes(bundle_bytes)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(item for item in package.rglob("*") if item.is_file()):
                archive.write(path, path.relative_to(package).as_posix())
            if unsafe_member:
                archive.writestr("../escape", b"spoof")
        record["evidence_sha256"] = release.sha256_file(archive_path)

    def make_qualification(
        self,
        manifest_digest: str,
        config_digests: dict[str, str],
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "candidate_version": self.VERSION,
            "candidate_source_sha": self.SOURCE_SHA,
            "candidate_manifest_sha256": manifest_digest,
            "candidate_artifact_digest": self.CANDIDATE_ARTIFACT_DIGEST,
            "status": "QUALIFIED",
            "qualification_requirements": self.qualification_requirements(),
            "project_operated_targets": [
                self.result(ecosystem, manifest_digest, config_digests[ecosystem])
                for ecosystem in ("python", "node", "rust")
            ],
            "independent_results": [
                self.result("rust", manifest_digest, config_digests["rust"], independent=True)
            ],
            "blocking_reason": None,
        }

    def add_qualification(
        self,
        directory: Path,
        manifest_digest: str,
        config_digests: dict[str, str],
    ) -> str:
        release.write_json(
            directory / release.QUALIFICATION_NAME,
            self.make_qualification(manifest_digest, config_digests),
        )
        digest = release.sha256_file(directory / release.QUALIFICATION_NAME)
        release.create_run_binding(
            argparse.Namespace(
                output=str(directory / release.QUALIFICATION_RUN_BINDING_NAME),
                mode="qualification",
                run_id="234",
                run_attempt="1",
                workflow_ref="owner/repo/.github/workflows/release.yml@refs/heads/master",
                candidate_run_id="123",
                candidate_manifest_sha256=manifest_digest,
                qualification_index_sha256=digest,
            )
        )
        return digest

    def test_external_configs_are_frozen_from_preregistered_paths_and_digests(self) -> None:
        repository_root = self.root / "repository"
        external_root = repository_root / "docs" / "qualification" / "external"
        external_root.mkdir(parents=True)
        targets: list[dict[str, object]] = []
        sources: dict[str, Path] = {}
        for ecosystem, (repository, source_sha, config_path) in self.TARGETS.items():
            source = repository_root / Path(*Path(config_path).parts)
            source.write_text(
                f"version: 1\nproject:\n  ecosystem: {ecosystem}\n",
                encoding="utf-8",
            )
            sources[ecosystem] = source
            targets.append(
                {
                    "ecosystem": ecosystem,
                    "repository": repository,
                    "source_sha": source_sha,
                    "config_path": config_path,
                    "config_sha256": release.sha256_file(source),
                    "status": "NOT_RUN",
                    "workflow_url": None,
                    "evidence_sha256": None,
                }
            )
        index = repository_root / "docs" / "qualification" / "EXTERNAL_EVIDENCE_INDEX.json"
        protocol = repository_root / "docs" / "qualification" / "EXTERNAL_PROTOCOL.md"
        release.write_json(
            index,
            {
                "schema_version": 1,
                "candidate_version": self.VERSION,
                "candidate_source_sha": None,
                "candidate_manifest_sha256": None,
                "status": "BLOCKED_EXTERNAL",
                "qualification_requirements": self.qualification_requirements(),
                "project_operated_targets": targets,
                "independent_results": [],
                "blocking_reason": "Independent execution is pending.",
            },
        )
        protocol.write_text("# Exact preregistration\n", encoding="utf-8")
        output = self.root / "frozen"
        release.copy_frozen_external_inputs(
            argparse.Namespace(
                index=str(index),
                protocol=str(protocol),
                repository_root=str(repository_root),
                output=str(output),
            )
        )
        for ecosystem, source in sources.items():
            self.assertEqual(
                (output / release.EXTERNAL_CONFIG_SNAPSHOTS[ecosystem]).read_bytes(),
                source.read_bytes(),
            )
        release.validate_frozen_external_snapshot(
            output / release.EXTERNAL_SNAPSHOT,
            self.VERSION,
            "owner",
        )

        sources["python"].write_text("tampered: true\n", encoding="utf-8")
        with self.assertRaises(release.ReleaseError):
            release.copy_frozen_external_inputs(
                argparse.Namespace(
                    index=str(index),
                    protocol=str(protocol),
                    repository_root=str(repository_root),
                    output=str(self.root / "tampered-freeze"),
                )
            )

    def test_candidate_and_promotion_round_trip_has_one_complete_release_checksum(self) -> None:
        directory, lock, config_digests = self.make_payload()
        manifest_digest = self.create_candidate(directory, lock)
        self.assertNotIn(release.CHECKSUMS_NAME, {path.name for path in directory.iterdir()})
        release.verify_candidate_directory(
            directory,
            expected_manifest_sha256=manifest_digest,
            expected_source_sha=self.SOURCE_SHA,
            expected_run_id="123",
            expected_version=self.VERSION,
            expected_repository="owner/repo",
            lock_path=lock,
        )
        qualification_digest = self.add_qualification(directory, manifest_digest, config_digests)
        release.create_promotion(
            argparse.Namespace(
                directory=str(directory),
                output=str(directory / release.ATTESTATION_NAME),
                lock=str(lock),
                tag_name="v0.2.0",
                tag_object_sha="2" * 40,
                peeled_commit_sha=self.SOURCE_SHA,
                candidate_run_id="123",
                candidate_manifest_sha256=manifest_digest,
                candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                qualification_run_id="234",
                qualification_index_sha256=qualification_digest,
                qualification_artifact_digest=self.QUALIFICATION_ARTIFACT_DIGEST,
                project_owner="owner",
                repository="owner/repo",
                run_id="456",
                run_attempt="1",
                workflow_ref="owner/repo/.github/workflows/release.yml@refs/tags/v0.2.0",
            )
        )
        checksums = release.parse_checksums(directory / release.CHECKSUMS_NAME)
        self.assertEqual(
            sorted(checksums),
            sorted(set(release.release_file_names(self.VERSION)) - {release.CHECKSUMS_NAME}),
        )
        for required in (
            release.MANIFEST_NAME,
            release.CANDIDATE_RUN_BINDING_NAME,
            release.QUALIFICATION_NAME,
            release.QUALIFICATION_RUN_BINDING_NAME,
            release.ATTESTATION_NAME,
        ):
            self.assertIn(required, checksums)
        release.verify_release(
            argparse.Namespace(
                directory=str(directory),
                lock=str(lock),
                tag_name="v0.2.0",
                tag_object_sha="2" * 40,
                peeled_commit_sha=self.SOURCE_SHA,
                candidate_run_id="123",
                candidate_manifest_sha256=manifest_digest,
                candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                qualification_run_id="234",
                qualification_index_sha256=qualification_digest,
                qualification_artifact_digest=self.QUALIFICATION_ARTIFACT_DIGEST,
                project_owner="owner",
                repository="owner/repo",
            )
        )

    def test_candidate_rejects_extra_and_mutated_files(self) -> None:
        directory, lock, _ = self.make_payload()
        digest = self.create_candidate(directory, lock)
        extra = directory / "SHA256SUMS.txt"
        extra.write_text("candidate checksum is forbidden\n", encoding="utf-8")
        with self.assertRaises(release.ReleaseError):
            release.verify_candidate_directory(directory, expected_manifest_sha256=digest)
        extra.unlink()
        archive = directory / release.archive_name(self.VERSION, "x86_64-unknown-linux-gnu")
        archive.write_bytes(b"mutated")
        with self.assertRaises(release.ReleaseError):
            release.verify_candidate_directory(directory, expected_manifest_sha256=digest)

    def test_tag_metadata_is_strict_unique_and_binds_artifact_digests(self) -> None:
        fields = release.parse_tag_fields(
            "TomorrowCI candidate promotion\n\n"
            "candidate-run-id: 123\n"
            f"candidate-manifest-sha256: {'a' * 64}\n"
            f"candidate-artifact-digest: sha256:{'c' * 64}\n"
            "qualification-run-id: 234\n"
            f"qualification-index-sha256: {'b' * 64}\n"
            f"qualification-artifact-digest: sha256:{'d' * 64}\n"
        )
        self.assertEqual(fields[2], "sha256:" + "c" * 64)
        self.assertEqual(fields[5], "sha256:" + "d" * 64)
        with self.assertRaises(release.ReleaseError):
            release.parse_tag_fields(
                "candidate-run-id: 123\n"
                "candidate-run-id: 456\n"
                f"candidate-manifest-sha256: {'a' * 64}\n"
                f"candidate-artifact-digest: sha256:{'c' * 64}\n"
                "qualification-run-id: 234\n"
                f"qualification-index-sha256: {'b' * 64}\n"
                f"qualification-artifact-digest: sha256:{'d' * 64}\n"
            )

    def validate_qualification_value(
        self,
        directory: Path,
        value: dict[str, object],
        manifest_digest: str,
    ) -> None:
        path = directory / release.QUALIFICATION_NAME
        release.write_json(path, value)
        release.validate_qualification_index_file(
            path,
            directory / release.EXTERNAL_SNAPSHOT,
            self.SOURCE_SHA,
            manifest_digest,
            self.CANDIDATE_ARTIFACT_DIGEST,
            self.VERSION,
            "owner",
            "owner/repo",
        )

    def test_qualification_spoofing_attacks_fail_closed(self) -> None:
        directory, lock, config_digests = self.make_payload()
        manifest_digest = self.create_candidate(directory, lock)
        base = self.make_qualification(manifest_digest, config_digests)
        honest_failure = copy.deepcopy(base)
        honest_failure["project_operated_targets"][0]["replay_exit_code"] = 3
        honest_failure["project_operated_targets"][0]["replay_expected_target_exit_code"] = 2
        honest_failure["project_operated_targets"][0]["replay_outcome_class"] = (
            "TARGET_FAILURE_REPRODUCED"
        )
        self.validate_qualification_value(directory, honest_failure, manifest_digest)
        attacks: list[tuple[str, callable]] = [
            (
                "self-owned target hidden in URL",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "repository", "https://github.com/owner/fake-external"
                ),
            ),
            (
                "non-canonical run URL",
                lambda value: value["project_operated_targets"][0].__setitem__("run_url", "not-a-url"),
            ),
            (
                "project run owned elsewhere",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "run_url", "https://github.com/attacker/run/actions/runs/456"
                ),
            ),
            (
                "evidence not bound to run",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "evidence_url",
                    "https://github.com/owner/external-qualification/actions/runs/999/artifacts/789",
                ),
            ),
            (
                "mutable image tag",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "image_digests", ["python:3.12"]
                ),
            ),
            (
                "wrong frozen config",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "config_sha256", "9" * 64
                ),
            ),
            (
                "wrong candidate artifact digest",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "candidate_artifact_digest", "sha256:" + "0" * 64
                ),
            ),
            (
                "signer workflow from another repository",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "signer_workflow", "attacker/repo/.github/workflows/fake.yml"
                ),
            ),
            (
                "alternate project workflow",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "signer_workflow", "owner/repo/.github/workflows/release.yml"
                ),
            ),
            (
                "same-owner different repository",
                lambda value: (
                    value["project_operated_targets"][0].__setitem__(
                        "run_url", "https://github.com/owner/other/actions/runs/456"
                    ),
                    value["project_operated_targets"][0].__setitem__(
                        "evidence_url",
                        "https://github.com/owner/other/actions/runs/456/artifacts/789",
                    ),
                    value["project_operated_targets"][0].__setitem__(
                        "signer_workflow", "owner/other/.github/workflows/external-targets.yml"
                    ),
                ),
            ),
            (
                "project workflow source differs from candidate",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "workflow_source_sha", "0" * 40
                ),
            ),
            (
                "blocked replay relabeled pass",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "replay_exit_code", 4
                ),
            ),
            (
                "replay 3 without a sealed target failure",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "replay_exit_code", 3
                ),
            ),
            (
                "replay target failure mislabeled pass",
                lambda value: value["project_operated_targets"][0].__setitem__(
                    "replay_expected_target_exit_code", 2
                ),
            ),
            (
                "project-owned auditor",
                lambda value: value["independent_results"][0].__setitem__(
                    "auditor_identity", "https://github.com/owner"
                ),
            ),
            (
                "independent release owned elsewhere",
                lambda value: value["independent_results"][0].__setitem__(
                    "release_url",
                    "https://github.com/attacker/audit/releases/tag/tomorrowci-independent-qualification-001",
                ),
            ),
            (
                "independent release asset tag mismatch",
                lambda value: value["independent_results"][0].__setitem__(
                    "evidence_url",
                    "https://github.com/external-auditor/independent-audit/releases/download/wrong/tomorrowci-independent-evidence.zip",
                ),
            ),
            (
                "independent Actions artifact transport",
                lambda value: value["independent_results"][0].__setitem__(
                    "evidence_url",
                    "https://github.com/external-auditor/independent-audit/actions/runs/456/artifacts/789",
                ),
            ),
            (
                "independent release id is not an integer",
                lambda value: value["independent_results"][0].__setitem__(
                    "release_id", "900"
                ),
            ),
            (
                "duplicate pre-registered target",
                lambda value: value["project_operated_targets"].__setitem__(
                    1, copy.deepcopy(value["project_operated_targets"][0])
                ),
            ),
            (
                "unknown result field",
                lambda value: value["project_operated_targets"][0].__setitem__("trust_me", True),
            ),
        ]
        for label, mutate in attacks:
            with self.subTest(label=label):
                attacked = copy.deepcopy(base)
                mutate(attacked)
                with self.assertRaises(release.ReleaseError):
                    self.validate_qualification_value(directory, attacked, manifest_digest)

    def test_blocked_qualification_cannot_promote(self) -> None:
        directory, lock, _ = self.make_payload()
        manifest_digest = self.create_candidate(directory, lock)
        blocked = release.load_json_object(
            directory / release.EXTERNAL_SNAPSHOT, "frozen index"
        )
        blocked["candidate_source_sha"] = self.SOURCE_SHA
        blocked["candidate_manifest_sha256"] = manifest_digest
        blocked["candidate_artifact_digest"] = self.CANDIDATE_ARTIFACT_DIGEST
        with self.assertRaises(release.ReleaseError):
            self.validate_qualification_value(directory, blocked, manifest_digest)

    def test_live_result_binds_public_run_raw_artifact_and_sealed_replay(self) -> None:
        record = self.result(
            "python",
            "a" * 64,
            "b" * 64,
            replay_target_exit=2,
        )
        subject = release.qualification_attestation_subject(record)
        subject_bytes = (
            json.dumps(subject, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(subject_bytes).hexdigest(), record["result_sha256"])
        artifact_zip = self.root / "evidence.zip"
        self.write_receipt_rich_archive(artifact_zip, record, subject_bytes)
        record_path = self.root / "live-record.json"
        repository_path = self.root / "repository.json"
        run_path = self.root / "live-run.json"
        artifacts_path = self.root / "live-artifacts.json"
        release.write_json(record_path, record)
        release.write_json(
            repository_path,
            {
                "full_name": "owner/repo",
                "private": False,
                "html_url": "https://github.com/owner/repo",
            },
        )
        run = {
            "id": 456,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.SOURCE_SHA,
            "head_branch": "master",
            "run_attempt": 1,
            "html_url": record["run_url"],
            "path": ".github/workflows/external-targets.yml@refs/heads/master",
            "repository": {"full_name": "owner/repo"},
        }
        artifact = {
            "id": 789,
            "name": record["evidence_artifact_name"],
            "expired": False,
            "size_in_bytes": artifact_zip.stat().st_size,
            "digest": "sha256:" + str(record["evidence_sha256"]),
            "workflow_run": {
                "id": 456,
                "head_sha": self.SOURCE_SHA,
                "head_branch": "master",
            },
        }
        release.write_json(run_path, run)
        release.write_json(artifacts_path, {"artifacts": [artifact]})

        def validate(subject_name: str = "validated-subject.json") -> None:
            release.validate_live_result(
                argparse.Namespace(
                    record=str(record_path),
                    kind="project",
                    project_owner="owner",
                    project_repository="owner/repo",
                    candidate_source_sha=self.SOURCE_SHA,
                    project_default_branch="master",
                    repository_json=str(repository_path),
                    run_json=str(run_path),
                    artifacts_json=str(artifacts_path),
                    artifact_zip=str(artifact_zip),
                    subject_output=str(self.root / subject_name),
                )
            )

        validate()
        run["conclusion"] = "failure"
        release.write_json(run_path, run)
        with self.assertRaises(release.ReleaseError):
            validate("rejected-run-subject.json")
        run["conclusion"] = "success"
        run["head_branch"] = "attack"
        release.write_json(run_path, run)
        with self.assertRaises(release.ReleaseError):
            validate("rejected-branch-subject.json")
        run["head_branch"] = "master"
        run["run_attempt"] = 2
        release.write_json(run_path, run)
        with self.assertRaises(release.ReleaseError):
            validate("rejected-attempt-subject.json")
        run["run_attempt"] = 1
        release.write_json(run_path, run)
        artifact["digest"] = "sha256:" + "0" * 64
        release.write_json(artifacts_path, {"artifacts": [artifact]})
        with self.assertRaises(release.ReleaseError):
            validate("rejected-artifact-subject.json")

    def test_independent_live_result_binds_immutable_release_tag_asset_and_bundle(self) -> None:
        record = self.result(
            "rust",
            "a" * 64,
            "b" * 64,
            independent=True,
            replay_target_exit=2,
        )
        subject = release.qualification_attestation_subject(record)
        subject_bytes = (
            json.dumps(subject, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        bundle_bytes = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        artifact_zip = self.root / "independent-evidence.zip"

        self.write_receipt_rich_archive(
            artifact_zip, record, subject_bytes, bundle_bytes=bundle_bytes
        )
        record_path = self.root / "independent-record.json"
        repository_path = self.root / "independent-repository.json"
        run_path = self.root / "independent-run.json"
        release_path = self.root / "independent-release.json"
        release_asset_path = self.root / "independent-release-asset.json"
        tag_ref_path = self.root / "independent-tag-ref.json"
        release.write_json(record_path, record)
        release.write_json(
            repository_path,
            {
                "full_name": "external-auditor/independent-audit",
                "private": False,
                "html_url": "https://github.com/external-auditor/independent-audit",
            },
        )
        release.write_json(
            run_path,
            {
                "id": 456,
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "8" * 40,
                "head_branch": "main",
                "run_attempt": 1,
                "html_url": record["run_url"],
                "path": ".github/workflows/external-qualification.yml@refs/heads/main",
                "repository": {"full_name": "external-auditor/independent-audit"},
            },
        )
        release_value = {
            "id": 900,
            "url": "https://api.github.com/repos/external-auditor/independent-audit/releases/900",
            "html_url": record["release_url"],
            "tag_name": record["release_tag"],
            "target_commitish": "8" * 40,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "assets": [
                {
                    "id": 901,
                    "url": "https://api.github.com/repos/external-auditor/independent-audit/releases/assets/901",
                    "name": record["evidence_artifact_name"],
                    "state": "uploaded",
                    "browser_download_url": record["evidence_url"],
                    "digest": "sha256:" + str(record["evidence_sha256"]),
                    "size": artifact_zip.stat().st_size,
                }
            ],
        }
        release_asset_value = copy.deepcopy(release_value["assets"][0])
        tag_ref = {
            "ref": f"refs/tags/{record['release_tag']}",
            "url": (
                "https://api.github.com/repos/external-auditor/independent-audit/git/refs/tags/"
                f"{record['release_tag']}"
            ),
            "object": {
                "type": "commit",
                "sha": "8" * 40,
                "url": (
                    "https://api.github.com/repos/external-auditor/independent-audit/git/commits/"
                    + "8" * 40
                ),
            },
        }
        release.write_json(release_path, release_value)
        release.write_json(release_asset_path, release_asset_value)
        release.write_json(tag_ref_path, tag_ref)

        def validate(suffix: str) -> None:
            release.validate_live_result(
                argparse.Namespace(
                    record=str(record_path),
                    kind="independent",
                    project_owner="owner",
                    project_repository="owner/repo",
                    candidate_source_sha=self.SOURCE_SHA,
                    project_default_branch="master",
                    repository_json=str(repository_path),
                    run_json=str(run_path),
                    artifacts_json=None,
                    release_json=str(release_path),
                    release_asset_json=str(release_asset_path),
                    tag_ref_json=str(tag_ref_path),
                    artifact_zip=str(artifact_zip),
                    subject_output=str(self.root / f"{suffix}-subject.json"),
                    bundle_output=str(self.root / f"{suffix}-bundle.jsonl"),
                    extract_output=str(self.root / f"{suffix}-extracted"),
                )
            )

        validate("accepted")
        self.assertEqual((self.root / "accepted-subject.json").read_bytes(), subject_bytes)
        self.assertEqual((self.root / "accepted-bundle.jsonl").read_bytes(), bundle_bytes)
        self.assertTrue(
            (
                self.root
                / "accepted-extracted"
                / "evidence"
                / "runs"
                / str(record["evidence_run_id"])
                / "checksums.txt"
            ).is_file()
        )

        release_value["immutable"] = False
        release.write_json(release_path, release_value)
        with self.assertRaises(release.ReleaseError):
            validate("mutable-release")
        release_value["immutable"] = True

        tag_ref["object"]["sha"] = "9" * 40
        release.write_json(tag_ref_path, tag_ref)
        release.write_json(release_path, release_value)
        with self.assertRaises(release.ReleaseError):
            validate("moved-tag")
        tag_ref["object"]["sha"] = "8" * 40

        release_value["assets"][0]["browser_download_url"] = (
            "https://github.com/attacker/repo/releases/download/spoof/evidence.zip"
        )
        release.write_json(tag_ref_path, tag_ref)
        release.write_json(release_path, release_value)
        with self.assertRaises(release.ReleaseError):
            validate("spoofed-asset")
        release_value["assets"][0]["browser_download_url"] = record["evidence_url"]

        release_asset_value["digest"] = "sha256:" + "0" * 64
        release.write_json(release_asset_path, release_asset_value)
        release.write_json(release_path, release_value)
        with self.assertRaises(release.ReleaseError):
            validate("spoofed-asset-endpoint")
        release_asset_value["digest"] = "sha256:" + str(record["evidence_sha256"])
        release.write_json(release_asset_path, release_asset_value)

        self.write_receipt_rich_archive(
            artifact_zip,
            record,
            subject_bytes,
            bundle_bytes=bundle_bytes,
            include_bundle=False,
        )
        release.write_json(record_path, record)
        release_value["assets"][0]["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_value["assets"][0]["size"] = artifact_zip.stat().st_size
        release_asset_value["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_asset_value["size"] = artifact_zip.stat().st_size
        release.write_json(release_path, release_value)
        release.write_json(release_asset_path, release_asset_value)
        with self.assertRaises(release.ReleaseError):
            validate("missing-bundle")

        self.write_receipt_rich_archive(
            artifact_zip,
            record,
            subject_bytes,
            bundle_bytes=bundle_bytes,
            unsafe_member=True,
        )
        release.write_json(record_path, record)
        release_value["assets"][0]["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_value["assets"][0]["size"] = artifact_zip.stat().st_size
        release_asset_value["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_asset_value["size"] = artifact_zip.stat().st_size
        release.write_json(release_path, release_value)
        release.write_json(release_asset_path, release_asset_value)
        with self.assertRaises(release.ReleaseError):
            validate("unsafe-zip")

        with zipfile.ZipFile(artifact_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(release.QUALIFICATION_RESULT_NAME, subject_bytes)
            archive.writestr(
                "evidence/runs/external-run/scenarios/future/result.json",
                json.dumps(
                    {
                        "scenario_id": "future",
                        "exit_code": 2,
                        "signal": None,
                        "timed_out": False,
                        "blocked_reason": None,
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
            archive.writestr(release.QUALIFICATION_ATTESTATION_BUNDLE_NAME, bundle_bytes)
        record["evidence_sha256"] = release.sha256_file(artifact_zip)
        release.write_json(record_path, record)
        release_value["assets"][0]["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_value["assets"][0]["size"] = artifact_zip.stat().st_size
        release_asset_value["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_asset_value["size"] = artifact_zip.stat().st_size
        release.write_json(release_path, release_value)
        release.write_json(release_asset_path, release_asset_value)
        with self.assertRaises(release.ReleaseError):
            validate("minimal-zip")

        self.write_receipt_rich_archive(
            artifact_zip,
            record,
            subject_bytes,
            bundle_bytes=bundle_bytes,
            tamper_receipt_after_seal=True,
        )
        release.write_json(record_path, record)
        release_value["assets"][0]["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_value["assets"][0]["size"] = artifact_zip.stat().st_size
        release_asset_value["digest"] = "sha256:" + str(record["evidence_sha256"])
        release_asset_value["size"] = artifact_zip.stat().st_size
        release.write_json(release_path, release_value)
        release.write_json(release_asset_path, release_asset_value)
        with self.assertRaises(release.ReleaseError):
            validate("tampered-receipt")

    def test_external_project_results_are_frozen_and_never_independent(self) -> None:
        candidate, lock, config_digests = self.make_payload()
        manifest_digest = self.create_candidate(candidate, lock)
        plan_output = self.root / "plan-output.txt"
        release.external_target_plan(
            argparse.Namespace(
                candidate_dir=str(candidate),
                expected_manifest_sha256=manifest_digest,
                expected_candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                expected_source_sha=self.SOURCE_SHA,
                expected_run_id="123",
                expected_version=self.VERSION,
                expected_repository="owner/repo",
                project_owner="owner",
                ecosystem="python",
                lock=str(lock),
                github_output=str(plan_output),
            )
        )
        plan = dict(
            line.split("=", 1)
            for line in plan_output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(plan["repository"], self.TARGETS["python"][0])
        self.assertEqual(plan["source_sha"], self.TARGETS["python"][1])

        selection = {
            "config_sha256": config_digests["python"],
            "ecosystem": "python",
            "engine": "docker",
            "engine_version": "28.0.4",
            "evidence_run_id": "sealed-run",
            "image_digests": [
                "docker.io/library/python:3.12-bookworm@sha256:" + "4" * 64
            ],
            "replay_expected_cli_exit_code": 3,
            "replay_expected_target_exit_code": 2,
            "replay_outcome_class": "TARGET_FAILURE_REPRODUCED",
            "replay_scenario_id": "python312",
            "repository": self.TARGETS["python"][0],
            "scan_exit_code": 3,
            "source_sha": self.TARGETS["python"][1],
            "workspace": str(self.root / "workspace"),
        }
        selection_path = self.root / "selection.json"
        release.write_json(selection_path, selection)
        subject_path = self.root / "qualification-result.subject.json"
        subject_arguments = argparse.Namespace(
            selection=str(selection_path),
            candidate_manifest_sha256=manifest_digest,
            candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
            candidate_source_sha=self.SOURCE_SHA,
            first_replay_exit_code="3",
            second_replay_exit_code="3",
            evidence_artifact_name="tomorrowci-project-evidence-python",
            run_url="https://github.com/owner/repo/actions/runs/456",
            run_attempt="2",
            signer_workflow="owner/repo/.github/workflows/external-targets.yml",
            workflow_source_sha=self.SOURCE_SHA,
            project_owner="owner",
            project_repository="owner/repo",
            output=str(subject_path),
            github_output=None,
        )
        release.create_external_subject(subject_arguments)
        final_path = self.root / "qualification-result.final.json"
        release.finalize_external_result(
            argparse.Namespace(
                subject=str(subject_path),
                artifact_id="789",
                artifact_digest="sha256:" + "5" * 64,
                artifact_url="https://github.com/owner/repo/actions/runs/456/artifacts/789",
                candidate_source_sha=self.SOURCE_SHA,
                project_owner="owner",
                project_repository="owner/repo",
                output=str(final_path),
            )
        )
        final = release.load_json_object(final_path, "final external result")
        self.assertNotIn("independent", final)
        self.assertNotIn("auditor_identity", final)
        self.assertEqual(final["replay_exit_code"], 3)
        blocked_arguments = copy.deepcopy(subject_arguments)
        blocked_arguments.first_replay_exit_code = "4"
        blocked_arguments.second_replay_exit_code = "4"
        blocked_arguments.output = str(self.root / "blocked-subject.json")
        with self.assertRaises(release.ReleaseError):
            release.create_external_subject(blocked_arguments)

        result_paths: list[str] = []
        for ecosystem in ("python", "node", "rust"):
            path = self.root / f"{ecosystem}-result.json"
            release.write_json(
                path,
                self.result(ecosystem, manifest_digest, config_digests[ecosystem]),
            )
            result_paths.append(str(path))
        combined = self.root / "combined"
        release.combine_project_results(
            argparse.Namespace(
                candidate_dir=str(candidate),
                expected_manifest_sha256=manifest_digest,
                candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                expected_source_sha=self.SOURCE_SHA,
                expected_run_id="123",
                expected_version=self.VERSION,
                expected_repository="owner/repo",
                project_owner="owner",
                lock=str(lock),
                result=result_paths,
                output=str(combined),
                github_output=None,
            )
        )
        aggregate = release.load_json_object(
            combined / release.PROJECT_RESULTS_NAME, "combined project results"
        )
        self.assertEqual(aggregate["status"], "QUALIFIED_PROJECT_OPERATED")
        self.assertNotIn("independent_results", aggregate)

    def test_prepare_external_replay_requires_clean_pinned_v2_horizon(self) -> None:
        checkout = self.root / "checkout"
        checkout.mkdir()
        config = self.root / "external.yml"
        config.write_text("version: 1\n", encoding="utf-8")
        evidence = self.root / "external-evidence"
        run_id = "sealed-run"
        run_directory = evidence / "runs" / run_id
        workspace = evidence / "work" / "workspaces" / run_id
        workspace.mkdir(parents=True)
        run_directory.mkdir(parents=True)
        source_sha = self.TARGETS["python"][1]
        release.write_json(
            run_directory / "run.json",
            {
                "run_id": run_id,
                "status": "COMPLETED",
                "repository": {
                    "source": str(checkout.resolve()),
                    "path": str(checkout.resolve()),
                    "commit_sha": source_sha,
                    "is_remote": False,
                    "workspace_copy": str(workspace.resolve()),
                },
                "detection": {"ecosystem": "python"},
            },
        )
        release.write_json(
            run_directory / "source-manifest.json",
            {
                "schema_version": 2,
                "commit_sha": source_sha,
                "dirty": False,
                "identity_kind": "git_commit",
            },
        )
        release.write_json(
            run_directory / "frontier.json",
            {"observed": True, "scenario_id": "python312"},
        )
        release.write_json(run_directory / "verdicts.json", {"unused": True})
        for scenario_id, image, target_exit in (
            ("baseline", "python:3.11-bookworm", 0),
            ("python312", "python:3.12-bookworm", 2),
        ):
            scenario = run_directory / "scenarios" / scenario_id
            scenario.mkdir(parents=True)
            release.write_json(
                scenario / "replay-manifest-v2.json",
                {
                    "schema_version": 2,
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "source_manifest_sha256": "sha256:" + "1" * 64,
                    "config_sha256": "sha256:" + "2" * 64,
                    "image_ref": image,
                    "image_digest": "sha256:" + "3" * 64,
                    "engine": {"name": "docker", "server_version": "28.0.4"},
                },
            )
            release.write_json(
                scenario / "result.json",
                {
                    "scenario_id": scenario_id,
                    "exit_code": target_exit,
                    "signal": None,
                    "timed_out": False,
                    "blocked_reason": None,
                },
            )
        release.write_json(
            run_directory / "scenarios" / "python312" / "replay-qualification.json",
            {
                "schema_version": 2,
                "run_id": run_id,
                "scenario_id": "python312",
                "replay_attempts": [{"ordinal": 1}, {"ordinal": 2}],
                "replay_equivalence": [
                    {"equivalent": True, "mismatches": []},
                    {"equivalent": True, "mismatches": []},
                ],
                "equivalent": True,
            },
        )
        output = self.root / "external-selection.json"
        github_output = self.root / "external-output.txt"
        arguments = argparse.Namespace(
            evidence_root=str(evidence),
            checkout=str(checkout),
            config=str(config),
            config_sha256=release.sha256_file(config),
            ecosystem="python",
            repository=self.TARGETS["python"][0],
            source_sha=source_sha,
            scan_exit_code="3",
            output=str(output),
            github_output=str(github_output),
        )
        release.prepare_external_replay(arguments)
        selection = release.load_json_object(output, "external selection")
        self.assertEqual(selection["replay_expected_cli_exit_code"], 3)
        self.assertEqual(selection["replay_expected_target_exit_code"], 2)
        self.assertIn("python:3.12-bookworm@sha256:", "\n".join(selection["image_digests"]))
        subject = self.root / "external-subject.json"
        release.create_external_subject(
            argparse.Namespace(
                selection=str(output),
                candidate_manifest_sha256="a" * 64,
                candidate_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                candidate_source_sha=self.SOURCE_SHA,
                first_replay_exit_code="3",
                second_replay_exit_code="3",
                evidence_artifact_name="tomorrowci-project-evidence-python",
                run_url="https://github.com/owner/repo/actions/runs/456",
                run_attempt="1",
                signer_workflow="owner/repo/.github/workflows/external-targets.yml",
                workflow_source_sha=self.SOURCE_SHA,
                project_owner="owner",
                project_repository="owner/repo",
                output=str(subject),
                github_output=None,
            )
        )
        staged = self.root / "staged"
        release.stage_external_evidence(
            argparse.Namespace(
                evidence_root=str(evidence),
                selection=str(output),
                subject=str(subject),
                output=str(staged),
            )
        )
        archive = self.root / "external-evidence.zip"
        subject_record = release.load_json_object(subject, "external subject")
        self.write_receipt_rich_archive(
            archive,
            subject_record,
            subject.read_bytes(),
        )
        release.validate_external_evidence_archive(
            argparse.Namespace(
                artifact_zip=str(archive),
                expected_digest="sha256:" + release.sha256_file(archive),
                selection=str(output),
                subject=str(subject),
            )
        )
        with self.assertRaises(release.ReleaseError):
            release.validate_external_evidence_archive(
                argparse.Namespace(
                    artifact_zip=str(archive),
                    expected_digest="sha256:" + "0" * 64,
                    selection=str(output),
                    subject=str(subject),
                )
            )
        tampered = release.load_json_object(run_directory / "run.json", "run")
        tampered["repository"]["commit_sha"] = "f" * 40
        release.write_json(run_directory / "run.json", tampered)
        output.unlink()
        with self.assertRaises(release.ReleaseError):
            release.prepare_external_replay(arguments)

    def test_workflow_run_blocks_never_interpolate_dispatch_inputs(self) -> None:
        repository = MODULE_PATH.parents[2]
        for relative in (
            ".github/workflows/release.yml",
            ".github/workflows/external-targets.yml",
        ):
            lines = (repository / relative).read_text(encoding="utf-8").splitlines()
            workflow_text = "\n".join(lines)
            self.assertNotIn("mapfile", workflow_text, relative)
            self.assertNotIn("readarray", workflow_text, relative)
            run_indent: int | None = None
            run_lines: list[str] = []
            blocks: list[str] = []
            for line in lines:
                indentation = len(line) - len(line.lstrip(" "))
                if run_indent is not None and line.strip() and indentation <= run_indent:
                    blocks.append("\n".join(run_lines))
                    run_indent = None
                    run_lines = []
                if line.lstrip().startswith("run: |"):
                    run_indent = indentation
                    continue
                if run_indent is not None:
                    run_lines.append(line)
            if run_indent is not None:
                blocks.append("\n".join(run_lines))
            self.assertTrue(blocks, relative)
            for index, block in enumerate(blocks):
                self.assertNotIn("${{ inputs.", block, f"{relative} run block {index}")
                self.assertNotIn("|| true", block, f"{relative} run block {index}")

    def test_upload_artifact_hex_outputs_are_normalized_before_canonical_use(self) -> None:
        repository = MODULE_PATH.parents[2]
        release_workflow = (repository / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        external_workflow = (repository / ".github/workflows/external-targets.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            release_workflow.count('ARTIFACT_DIGEST="sha256:$ARTIFACT_DIGEST_HEX"'),
            1,
        )
        self.assertEqual(
            release_workflow.count(
                'QUALIFICATION_ARTIFACT_DIGEST="sha256:$QUALIFICATION_ARTIFACT_DIGEST_HEX"'
            ),
            1,
        )
        self.assertEqual(
            external_workflow.count('ARTIFACT_DIGEST="sha256:$ARTIFACT_DIGEST_HEX"'),
            3,
        )
        self.assertNotIn(
            "subject-digest: ${{ steps.",
            external_workflow,
        )
        self.assertEqual(
            external_workflow.count("subject-digest: sha256:${{ steps."),
            2,
        )

    def test_external_candidate_doctor_accepts_aligned_ok_output(self) -> None:
        repository = MODULE_PATH.parents[2]
        workflow = (repository / ".github/workflows/external-targets.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "grep -Eq '^sandbox[[:space:]]+\\[ok\\][[:space:]]+.+'",
            workflow,
        )
        self.assertNotIn('$doctor_output" != *"sandbox [ok]"*', workflow)

    def test_release_workflow_revalidates_independent_receipts_with_candidate(self) -> None:
        repository = MODULE_PATH.parents[2]
        workflow = (repository / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('scenario_id="$(jq -er .replay_scenario_id "$record")"', workflow)
        self.assertNotIn('scenario_id="$(jq -er .scenario_id "$record")"', workflow)
        self.assertIn('--extract-output "live-extracted/$stem"', workflow)
        self.assertIn('"$candidate_binary" verify "$original_run"', workflow)
        self.assertIn('"$candidate_binary" verify "$receipt_directory"', workflow)
        self.assertIn('"$candidate_binary" replay-qualify', workflow)
        self.assertEqual(workflow.count('comm -13 "$before_receipts" "$after_receipts"'), 2)
        self.assertEqual(workflow.count('comm -23 "$before_receipts" "$after_receipts"'), 2)
        self.assertIn("--max-filesize 1073741824", workflow)
        self.assertIn("--proto-redir '=https'", workflow)

    def test_windows_release_builds_are_reproducible_and_fail_with_diagnostics(self) -> None:
        repository = MODULE_PATH.parents[2]
        release_workflow = (repository / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        ci_workflow = (repository / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        for workflow in (release_workflow, ci_workflow):
            self.assertIn(
                '$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = "-C link-arg=/Brepro"',
                workflow,
            )
            self.assertIn("clean --target-dir $targetDir", workflow)
            self.assertIn("the two clean Windows release builds differ", workflow)
            self.assertIn("windows-reproducibility-diagnostics", workflow)
            self.assertIn("steps.windows_repro.outcome == 'failure'", workflow)
            self.assertIn("include-hidden-files: true", workflow)

    def test_preregistered_external_config_digests_match_repository_bytes(self) -> None:
        repository = MODULE_PATH.parents[2]
        attributes = (repository / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("docs/qualification/external/*.yml text eol=lf", attributes.splitlines())
        index = json.loads(
            (repository / "docs/qualification/EXTERNAL_EVIDENCE_INDEX.json").read_text(
                encoding="utf-8"
            )
        )
        protocol = (
            repository / "docs/qualification/EXTERNAL_PROTOCOL.md"
        ).read_text(encoding="utf-8")
        targets = index.get("project_operated_targets")
        self.assertIsInstance(targets, list)
        self.assertEqual(len(targets), 3)
        seen: set[str] = set()
        for target in targets:
            self.assertIsInstance(target, dict)
            ecosystem = target.get("ecosystem")
            config_path = target.get("config_path")
            expected = target.get("config_sha256")
            self.assertIsInstance(ecosystem, str)
            self.assertIsInstance(config_path, str)
            self.assertIsInstance(expected, str)
            self.assertNotIn(ecosystem, seen)
            seen.add(ecosystem)

            # Git stores these text fixtures with LF. Normalize only checkout
            # CRLF so this contract test is identical on Windows and Linux.
            contents = (repository / config_path).read_bytes().replace(b"\r\n", b"\n")
            self.assertNotIn(b"\r", contents)
            self.assertEqual(hashlib.sha256(contents).hexdigest(), expected, ecosystem)
            self.assertEqual(protocol.count(f"`{expected}`"), 1, ecosystem)
        self.assertEqual(seen, {"python", "node", "rust"})

    def test_validate_run_binds_inputs_attempt_workflow_and_server_digest(self) -> None:
        run = {
            "id": 123,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.SOURCE_SHA,
            "head_branch": "master",
            "path": ".github/workflows/release.yml",
            "run_attempt": 2,
            "repository": {"full_name": "owner/repo"},
            "inputs": {
                "mode": "candidate",
                "dry_run": True,
                "candidate_run_id": "",
                "candidate_manifest_sha256": "",
                "qualification_index_json": "",
            },
            "referenced_workflows": [
                {
                    "path": "owner/repo/.github/workflows/ci.yml@refs/heads/master",
                    "sha": self.SOURCE_SHA,
                }
            ],
        }
        artifacts = {
            "artifacts": [
                {
                    "id": 999,
                    "name": release.ARTIFACT_NAME,
                    "expired": False,
                    "size_in_bytes": 1024,
                    "digest": self.CANDIDATE_ARTIFACT_DIGEST,
                    "workflow_run": {
                        "id": 123,
                        "head_sha": self.SOURCE_SHA,
                        "head_branch": "master",
                    },
                }
            ]
        }
        run_path = self.root / "run.json"
        artifacts_path = self.root / "artifacts.json"
        binding_path = self.root / release.CANDIDATE_RUN_BINDING_NAME
        release.write_json(run_path, run)
        release.write_json(artifacts_path, artifacts)
        release.create_run_binding(
            argparse.Namespace(
                output=str(binding_path),
                mode="candidate",
                run_id="123",
                run_attempt="2",
                workflow_ref="owner/repo/.github/workflows/release.yml@refs/heads/master",
                candidate_run_id="",
                candidate_manifest_sha256="",
                qualification_index_sha256="",
            )
        )

        def args() -> argparse.Namespace:
            return argparse.Namespace(
                run_json=str(run_path),
                artifacts_json=str(artifacts_path),
                run_id="123",
                source_sha=self.SOURCE_SHA,
                default_branch="master",
                repository="owner/repo",
                artifact_name=release.ARTIFACT_NAME,
                expected_artifact_digest=self.CANDIDATE_ARTIFACT_DIGEST,
                expected_run_attempt="2",
                expected_workflow_ref="owner/repo/.github/workflows/release.yml@refs/heads/master",
                input_binding=str(binding_path),
                expected_mode="candidate",
                expected_candidate_run_id="",
                expected_candidate_manifest_sha256="",
                expected_qualification_input_sha256=None,
                require_referenced_workflow=".github/workflows/ci.yml",
                github_output=None,
            )

        release.validate_run(args())
        without_api_inputs = copy.deepcopy(run)
        without_api_inputs.pop("inputs")
        release.write_json(run_path, without_api_inputs)
        release.validate_run(args())
        binding = release.load_json_object(binding_path, "run binding")
        binding["inputs"]["dry_run"] = False
        release.write_json(binding_path, binding)
        with self.assertRaises(release.ReleaseError):
            release.validate_run(args())
        binding["inputs"]["dry_run"] = True
        release.write_json(binding_path, binding)
        release.write_json(run_path, run)
        attacks = (
            ("input", lambda: run["inputs"].__setitem__("dry_run", False)),
            ("attempt", lambda: run.__setitem__("run_attempt", 3)),
            ("artifact digest", lambda: artifacts["artifacts"][0].__setitem__("digest", "sha256:" + "0" * 64)),
            ("workflow sha", lambda: run["referenced_workflows"][0].__setitem__("sha", "0" * 40)),
        )
        for label, mutate in attacks:
            with self.subTest(label=label):
                original_run = copy.deepcopy(run)
                original_artifacts = copy.deepcopy(artifacts)
                mutate()
                release.write_json(run_path, run)
                release.write_json(artifacts_path, artifacts)
                with self.assertRaises(release.ReleaseError):
                    release.validate_run(args())
                run = original_run
                artifacts = original_artifacts

    def test_workspace_sbom_merge_is_deterministic_and_includes_adapter_example(self) -> None:
        lock, _ = self.make_lock_and_sbom()
        metadata = {
            "workspace_members": ["cli-id", "example-id"],
            "packages": [
                {"id": "cli-id", "name": "tomorrowci", "version": self.VERSION},
                {
                    "id": "example-id",
                    "name": "tomorrowci-adapter-example",
                    "version": self.VERSION,
                },
            ],
        }
        metadata_path = self.root / "metadata.json"
        release.write_json(metadata_path, metadata)
        serde = {
            "type": "library",
            "bom-ref": "pkg:cargo/serde@1.0.0",
            "name": "serde",
            "version": "1.0.0",
        }

        def member(name: str) -> dict[str, object]:
            reference = f"pkg:cargo/{name}@{self.VERSION}"
            return {
                "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "timestamp": "1970-01-01T00:00:00.000000000Z",
                    "tools": [{"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}],
                    "component": {
                        "type": "application" if name == "tomorrowci" else "library",
                        "bom-ref": reference,
                        "name": name,
                        "version": self.VERSION,
                    },
                },
                "components": [serde],
                "dependencies": [
                    {"ref": reference, "dependsOn": [serde["bom-ref"]]},
                    {"ref": serde["bom-ref"], "dependsOn": []},
                ],
            }

        inputs: list[str] = []
        for name in ("tomorrowci", "tomorrowci-adapter-example"):
            path = self.root / f"{name}.cdx.json"
            release.write_json(path, member(name))
            inputs.append(str(path))
        outputs = [self.root / "first.json", self.root / "second.json"]
        for output in outputs:
            release.merge_sboms(
                argparse.Namespace(
                    input=inputs,
                    metadata=str(metadata_path),
                    lock=str(lock),
                    output=str(output),
                    expected_version=self.VERSION,
                    source_date_epoch="0",
                )
            )
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
        merged = json.loads(outputs[0].read_text(encoding="utf-8"))
        names = {component["name"] for component in merged["components"]}
        self.assertIn("tomorrowci-adapter-example", names)
        with self.assertRaises(release.ReleaseError):
            release.merge_sboms(
                argparse.Namespace(
                    input=inputs[:1],
                    metadata=str(metadata_path),
                    lock=str(lock),
                    output=str(self.root / "missing.json"),
                    expected_version=self.VERSION,
                    source_date_epoch="0",
                )
            )

    def test_prepare_replay_binds_downloaded_scenario_to_checked_out_fixture(self) -> None:
        fixtures = self.root / "fixtures"
        fixture = fixtures / "sample"
        fixture.mkdir(parents=True)
        producer = fixture / "input.txt"
        producer.write_text("sealed producer\n", encoding="utf-8")
        evidence = self.root / "evidence"
        runs = evidence / "runs"
        runs.mkdir(parents=True)
        for index in range(6):
            run_id = f"run{index}"
            scenario = runs / run_id / "scenarios" / "future"
            scenario.mkdir(parents=True)
            release.write_json(
                runs / run_id / "run.json",
                {
                    "run_id": run_id,
                    "repository": {
                        "source": "/checkout/fixtures/sample",
                        "commit_sha": self.SOURCE_SHA,
                    },
                },
            )
            release.write_json(
                runs / run_id / "source-manifest.json",
                {
                    "schema_version": 2,
                    "commit_sha": self.SOURCE_SHA,
                    "files": [
                        {
                            "path": "input.txt",
                            "sha256": "sha256:" + release.sha256_file(producer),
                            "size_bytes": producer.stat().st_size,
                            "executable": False,
                        }
                    ],
                },
            )
            release.write_json(scenario / "replay-manifest-v2.json", {"schema_version": 2})
            release.write_json(
                scenario / "result.json",
                {
                    "scenario_id": "future",
                    "exit_code": 1 if index == 2 else 0,
                    "timed_out": False,
                    "blocked_reason": None,
                },
            )
            if index == 2:
                release.write_json(scenario / "replay-qualification.json", {"equivalent": True})
        measure = evidence / "measure"
        measure.mkdir()
        release.write_json(
            measure / "suite-report.json",
            {
                "tool_version": self.VERSION,
                "started_at": "2026-08-11T00:00:00Z",
                "finished_at": "2026-08-11T00:01:00Z",
                "engine_requested": "auto",
                "engine_available": True,
                "engine_detail": "docker 28.0.4",
                "fixtures": [
                    {
                        "id": fixture_id,
                        "path": f"fixtures/{fixture_id}",
                        "duration_ms": index,
                        "run_id": f"run{index}",
                        "evidence_dir": f".tomorrowci/runs/run{index}",
                        "claims": [{"status": "PASS"}],
                        "terminal_summary": "PASS",
                    }
                    for index, fixture_id in enumerate(release.ACCEPTANCE_FIXTURE_IDS)
                ],
                "ledger": {"claims": []},
                "trustworthy": True,
            },
        )
        patched_run = runs / "patched-run"
        patched_run.mkdir()
        release.write_json(patched_run / "run.json", {"run_id": "patched-run"})
        proof = evidence / "patches" / "proof" / "patch-proof.json"
        proof.parent.mkdir(parents=True)
        release.write_json(
            proof,
            {
                "schema_version": 2,
                "disposition": "QUALIFIED",
                "original_unchanged": True,
                "original": {"run_id": "run0"},
                "patched": {"run_id": "patched-run"},
            },
        )
        fixture_output = self.root / "fixture-run-ids.txt"
        all_output = self.root / "all-run-ids.txt"
        release.acceptance_runs(
            argparse.Namespace(
                evidence_root=str(evidence),
                fixture_output=str(fixture_output),
                all_output=str(all_output),
            )
        )
        self.assertEqual(len(fixture_output.read_text(encoding="utf-8").splitlines()), 6)
        self.assertEqual(
            set(all_output.read_text(encoding="utf-8").splitlines()),
            {*(f"run{index}" for index in range(6)), "patched-run"},
        )
        output = self.root / "github-output.txt"
        release.prepare_replay(
            argparse.Namespace(
                evidence_root=str(evidence),
                fixtures_root=str(fixtures),
                expected_source_sha=self.SOURCE_SHA,
                github_output=str(output),
            )
        )
        values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
        self.assertEqual(values["run_id"], "run2")
        self.assertEqual(values["expected_cli_exit_code"], "3")
        self.assertEqual(Path(values["workspace"]), fixture.resolve())
        unexpected = runs / "unregistered-run"
        unexpected.mkdir()
        with self.assertRaises(release.ReleaseError):
            release.acceptance_run_inventory(evidence)


if __name__ == "__main__":
    unittest.main()
