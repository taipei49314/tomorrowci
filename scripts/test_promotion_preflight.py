#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promotion_preflight as preflight


def write_nul_suffixed_inventory(
    archive: Path, *, names: set[str], aliased_name: str
) -> None:
    """Write an exact inventory with one raw NUL-suffixed member name."""

    placeholder = f"{aliased_name}Xhidden".encode()
    malicious = aliased_name.encode() + b"\0hidden"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name in sorted(names):
            stored_name = placeholder.decode() if name == aliased_name else name
            entry = zipfile.ZipInfo(stored_name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            bundle.writestr(entry, f"{name}\n".encode())
    data = archive.read_bytes()
    if len(placeholder) != len(malicious) or data.count(placeholder) != 2:
        raise AssertionError("ZIP test fixture did not contain two raw member names")
    archive.write_bytes(data.replace(placeholder, malicious))


class PromotionStateTests(unittest.TestCase):
    TAG_REF = "refs/tags/v0.2.0-alpha.1"
    TAG_OID = "a" * 40
    MARKER_REF = "refs/tags/tomorrowci-authorization/" + "b" * 64
    MARKER_OID = "c" * 40

    def state(self, observation: str) -> dict:
        return preflight.remote_state(
            observation,
            version_ref=self.TAG_REF,
            version_oid=self.TAG_OID,
            marker_ref=self.MARKER_REF,
            marker_oid=self.MARKER_OID,
        )

    def test_new_and_exact_idempotent_states(self) -> None:
        self.assertEqual(self.state("")["state"], "READY_FOR_ATOMIC_CREATE_ONLY")
        exact = (
            f"{self.TAG_OID}\t{self.TAG_REF}\n{self.MARKER_OID}\t{self.MARKER_REF}\n"
        )
        self.assertEqual(self.state(exact)["state"], "IDEMPOTENT_EXACT_PAIR")
        self.assertEqual(self.state(exact)["status"], preflight.DISABLED_STATUS)

    def test_partial_mismatch_duplicate_and_unknown_fail_closed(self) -> None:
        bad = (
            f"{self.TAG_OID}\t{self.TAG_REF}\n",
            f"{'d' * 40}\t{self.TAG_REF}\n{self.MARKER_OID}\t{self.MARKER_REF}\n",
            f"{self.TAG_OID}\t{self.TAG_REF}\n{self.TAG_OID}\t{self.TAG_REF}\n",
            f"{self.TAG_OID}\trefs/tags/unexpected\n",
        )
        for observation in bad:
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                self.state(observation)

    def test_ci_run_must_be_exact_successful_default_push(self) -> None:
        source = "d" * 40
        run = {
            "conclusion": "success",
            "event": "push",
            "head_branch": "master",
            "head_repository": {"full_name": "owner/repo"},
            "head_sha": source,
            "id": 123,
            "path": ".github/workflows/ci.yml",
            "repository": {"full_name": "owner/repo"},
            "run_attempt": 2,
            "status": "completed",
        }
        preflight.inspect_ci_run(
            run,
            repository="owner/repo",
            source_sha=source,
            run_id="123",
            run_attempt="2",
        )
        for field, value in (
            ("event", "pull_request"),
            ("conclusion", "failure"),
            ("head_sha", "e" * 40),
        ):
            changed = copy.deepcopy(run)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                preflight.inspect_ci_run(
                    changed,
                    repository="owner/repo",
                    source_sha=source,
                    run_id="123",
                    run_attempt="2",
                )

    def test_post_approval_repository_run_and_reviewer_identities(self) -> None:
        source = "d" * 40
        repository = {"default_branch": "master", "full_name": "owner/repo"}
        branch = {
            "object": {"sha": source, "type": "commit"},
            "ref": "refs/heads/master",
        }
        preflight.inspect_repository_head(
            repository, branch, repository="owner/repo", source_sha=source
        )
        run = {
            "actor": {"id": 11},
            "conclusion": None,
            "event": "workflow_dispatch",
            "head_branch": "master",
            "head_repository": {"full_name": "owner/repo"},
            "head_sha": source,
            "id": 123,
            "path": ".github/workflows/protected-exact-byte-promotion-v2.yml",
            "repository": {"full_name": "owner/repo"},
            "run_attempt": 2,
            "status": "in_progress",
            "triggering_actor": {"id": 12},
        }
        preflight.inspect_promotion_workflow_run(
            run,
            repository="owner/repo",
            source_sha=source,
            run_id="123",
            run_attempt="2",
        )
        retired = copy.deepcopy(run)
        retired["path"] = ".github/workflows/protected-exact-byte-promotion.yml"
        with self.assertRaisesRegex(ValueError, "path mismatch"):
            preflight.inspect_promotion_workflow_run(
                retired,
                repository="owner/repo",
                source_sha=source,
                run_id="123",
                run_attempt="2",
            )
        environment = {
            "deployment_branch_policy": {
                "custom_branch_policies": False,
                "protected_branches": True,
            },
            "id": 44,
            "name": "release",
            "protection_rules": [
                {
                    "prevent_self_review": True,
                    "reviewers": [{"reviewer": {"id": 99}, "type": "User"}],
                    "type": "required_reviewers",
                }
            ],
        }
        approvals = [
            {
                "environments": [{"id": 44, "name": "release"}],
                "state": "approved",
                "user": {"id": 99, "login": "independent-reviewer"},
            }
        ]
        identity = preflight.inspect_approval_history(
            approvals, environment_metadata=environment, run_metadata=run
        )
        self.assertEqual(identity["reviewers"][0]["id"], 99)
        changed = copy.deepcopy(approvals)
        changed[0]["user"] = {"id": 11, "login": "dispatcher"}
        with self.assertRaisesRegex(ValueError, "self-approved"):
            preflight.inspect_approval_history(
                changed, environment_metadata=environment, run_metadata=run
            )
        drift = copy.deepcopy(branch)
        drift["object"]["sha"] = "e" * 40
        with self.assertRaisesRegex(ValueError, "no longer names"):
            preflight.inspect_repository_head(
                repository, drift, repository="owner/repo", source_sha=source
            )

    def test_oci_input_binds_only_authoritative_manifest_digest(self) -> None:
        authoritative = "sha256:" + "1" * 64
        decoy = "sha256:" + "2" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-provenance.json"
            path.write_text(
                json.dumps(
                    {
                        "build": {"decoy_digest": decoy},
                        "oci": {"manifest": {"digest": authoritative}},
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                preflight.inspect_oci_manifest_digest(path, authoritative),
                authoritative,
            )
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                preflight.inspect_oci_manifest_digest(path, decoy)

    def test_oci_manifest_parse_rejects_duplicate_digest_keys(self) -> None:
        digest = "sha256:" + "1" * 64
        replacement = "sha256:" + "2" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image-provenance.json"
            path.write_text(
                '{"oci":{"manifest":{"digest":"'
                + digest
                + '","digest":"'
                + replacement
                + '"}}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                preflight.inspect_oci_manifest_digest(path, digest)


class AuthorizationMarkerTests(unittest.TestCase):
    AUTHORIZATION_ID = "b" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        (self.repo / "tracked.txt").write_text("candidate\n", encoding="utf-8")
        self._git("add", "tracked.txt")
        self._git("commit", "-q", "-m", "candidate")
        self.commit = self._git("rev-parse", "HEAD")
        self.marker_name = f"tomorrowci-authorization/{self.AUTHORIZATION_ID}"
        self.marker_ref = f"refs/tags/{self.marker_name}"
        self._annotated(self.marker_name, self.commit)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _annotated(self, name: str, target: str) -> None:
        self._git(
            "tag",
            "--no-sign",
            "--annotate",
            "--message",
            f"Consume authorization {self.AUTHORIZATION_ID}",
            name,
            target,
        )

    def inspect(self) -> dict:
        return preflight.inspect_authorization_marker(
            git_repo=self.repo,
            marker_ref=self.marker_ref,
            candidate_source_sha=self.commit,
            authorization_id=self.AUTHORIZATION_ID,
        )

    def test_accepts_exact_direct_annotated_marker(self) -> None:
        identity = self.inspect()
        self.assertEqual(identity["internal_name"], self.marker_name)
        self.assertEqual(identity["target_sha"], self.commit)
        self.assertEqual(identity["peeled_commit"], self.commit)

    def test_rejects_lightweight_marker(self) -> None:
        self._git("tag", "-d", self.marker_name)
        self._git("tag", self.marker_name, self.commit)
        with self.assertRaisesRegex(ValueError, "lightweight tag"):
            self.inspect()

    def test_rejects_marker_targeting_another_commit(self) -> None:
        self._git("tag", "-d", self.marker_name)
        (self.repo / "other.txt").write_text("other\n", encoding="utf-8")
        self._git("add", "other.txt")
        self._git("commit", "-q", "-m", "other")
        other = self._git("rev-parse", "HEAD")
        self._annotated(self.marker_name, other)
        with self.assertRaisesRegex(ValueError, "exact candidate commit"):
            self.inspect()

    def test_rejects_tag_object_with_an_alias_internal_name(self) -> None:
        self._annotated("authorization-alias", self.commit)
        alias_oid = self._git("rev-parse", "refs/tags/authorization-alias")
        self._git("update-ref", self.marker_ref, alias_oid)
        with self.assertRaisesRegex(ValueError, "internal name"):
            self.inspect()


class PromotionDispatchInputTests(unittest.TestCase):
    VALUE = {
        "candidate_run_attempt": "2",
        "candidate_run_id": "200",
        "ci_run_attempt": "1",
        "ci_run_id": "100",
        "platform_qualification_run_attempt": "3",
        "platform_qualification_run_id": "300",
    }

    def test_accepts_only_canonical_exact_run_coordinates(self) -> None:
        raw = json.dumps(self.VALUE, sort_keys=True, separators=(",", ":"))
        self.assertEqual(preflight.parse_dispatch_run_coordinates(raw), self.VALUE)

    def test_rejects_ambiguous_or_incomplete_run_coordinates(self) -> None:
        canonical = json.dumps(self.VALUE, sort_keys=True, separators=(",", ":"))
        cases = {
            "duplicate": canonical.replace(
                '"ci_run_id":"100"', '"ci_run_id":"100","ci_run_id":"101"'
            ),
            "missing": json.dumps(
                {key: value for key, value in self.VALUE.items() if key != "ci_run_id"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "unknown": json.dumps(
                {**self.VALUE, "extra": "1"}, sort_keys=True, separators=(",", ":")
            ),
            "numeric": canonical.replace('"ci_run_id":"100"', '"ci_run_id":100'),
            "zero": canonical.replace('"ci_run_id":"100"', '"ci_run_id":"0"'),
            "leading-zero": canonical.replace(
                '"ci_run_id":"100"', '"ci_run_id":"0100"'
            ),
            "noncanonical": json.dumps(self.VALUE, sort_keys=False),
        }
        for name, value in cases.items():
            with self.subTest(name=name):
                with self.assertRaises((ValueError, json.JSONDecodeError)):
                    preflight.parse_dispatch_run_coordinates(value)


class PromotionWorkflowStaticTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    WORKFLOW = ROOT / ".github/workflows/protected-exact-byte-promotion-v2.yml"

    def test_workflow_path_did_not_exist_at_any_historical_tag(self) -> None:
        tags = subprocess.run(
            ["git", "-C", str(self.ROOT), "tag", "--list"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertTrue(tags, "Fetch complete tag history before checking workflow retirement")
        relative = self.WORKFLOW.relative_to(self.ROOT).as_posix()
        for tag in tags:
            result = subprocess.run(
                ["git", "-C", str(self.ROOT), "cat-file", "-e", f"{tag}:{relative}"],
                check=False,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, f"workflow exists at {tag}")

    def test_retired_promotion_path_is_not_reintroduced(self) -> None:
        self.assertFalse(
            (self.ROOT / ".github/workflows/protected-exact-byte-promotion.yml").exists()
        )

    def test_permissions_concurrency_roll_forward_and_isolated_ghcr_gate(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        dispatch = text.split("    inputs:\n", 1)[1].split("\npermissions:", 1)[0]
        dispatch_inputs = [
            line.strip().removesuffix(":")
            for line in dispatch.splitlines()
            if line.startswith("      ") and not line.startswith("        ")
        ]
        self.assertLessEqual(len(dispatch_inputs), 10)
        self.assertEqual(len(dispatch_inputs), 8)
        self.assertIn("run_coordinates", dispatch_inputs)
        self.assertNotIn("\n  push:", text)
        self.assertIn("  actions: read\n  contents: read\n  packages: read\n", text)
        self.assertIn("group: protected-exact-byte-promotion", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("environment: release", text)
        self.assertIn("contents: write", text)
        self.assertIn("packages: write", text)
        self.assertNotIn("assert-publication-disabled", text)
        self.assertIn("assert-ghcr-nonclobber-write", text)
        self.assertIn("assert-release-publish-nonclobber", text)
        self.assertIn("inspect-authorization-marker", text)
        self.assertIn("inspect-oci-manifest", text)
        self.assertIn("scripts/external_policy_transport.py fetch", text)
        self.assertGreaterEqual(text.count("external-policy-transport.json"), 4)
        self.assertNotIn("expected-policy-sha256.txt", text)
        self.assertNotIn("preregistered-policy.json", text)
        self.assertIn("build-publication-plan", text)
        self.assertIn("ghcr-version-pages.json", text)
        self.assertIn("tag-promotion-attestation.json", text)
        self.assertIn("git tag --no-sign --annotate", text)
        self.assertIn("git push --atomic", text)
        self.assertIn("GIT_ASKPASS", text)
        self.assertNotIn("persist-credentials: true", text)
        self.assertNotIn("releases/tags", text)
        self.assertGreaterEqual(text.count("scripts/external_authorization.py"), 2)
        self.assertGreaterEqual(text.count("scripts/tag_promotion_attestation.py"), 2)
        self.assertIn("inspect-immutable-release-setting", text)
        self.assertIn("inspect-approval-history", text)
        self.assertIn("/approvals", text)
        self.assertIn("inspect-promotion-run", text)
        self.assertIn("inspect-repository-head", text)
        for platform_input in (
            "platform_qualification_run_id:",
            "platform_qualification_run_attempt:",
            "platform_qualification_identity_sha256:",
        ):
            self.assertIn(platform_input, text)
        self.assertGreaterEqual(text.count("inspect-platform-api"), 2)
        self.assertGreaterEqual(text.count("verify-platform-consumption"), 2)
        self.assertIn("verify-platform-plan-binding", text)
        self.assertGreaterEqual(
            text.count(
                'gh api "/repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip"'
            ),
            2,
        )
        self.assertIn("release-readback:", text)
        for runner in ("ubuntu-24.04", "macos-15", "windows-2025"):
            self.assertIn(f"os: {runner}", text)
        self.assertIn("image-readback:", text)
        self.assertIn("65532:65532", text)
        self.assertIn("org.opencontainers.image.revision", text)
        self.assertIn("status: READY", text)
        self.assertIn("inspect-doctor-output", text)
        self.assertGreaterEqual(text.count("artifact-ids:"), 2)
        self.assertIn("extract-prepared-state", text)
        self.assertEqual(text.count("extract-candidate"), 2)
        self.assertEqual(text.count("uses: actions/download-artifact@"), 2)
        self.assertNotIn(
            "name: protected-promotion-preflight-${{ github.run_id }}-attempt-${{ github.run_attempt }}",
            text.split("\n  write:", 1)[1],
        )
        self.assertIn(
            "CREATE_NONCLOBBER_DRAFT_PRERELEASE",
            preflight.inspect_release_state(
                [],
                tag_name="v1",
                target_commitish="d" * 40,
                release_name="n",
                body="b",
                expected_assets=[],
            )["state"],
        )
        self.assertRegex(
            preflight.ORAS_TOOL,
            r"^ghcr\.io/oras-project/oras@sha256:[0-9a-f]{64}$",
        )
        self.assertGreater(
            text.index("assert-ghcr-nonclobber-write"), text.index("\n  write:")
        )
        self.assertLess(
            text.index("assert-ghcr-nonclobber-write"),
            text.index("git push --atomic"),
        )
        global_gate = text.index("assert-ghcr-nonclobber-write")
        for mutation in (
            'gh api --method POST "/repos/$GITHUB_REPOSITORY/releases"',
            "cp --from-oci-layout",
            'gh api --method PATCH "$update"',
            "uploads.github.com --method POST",
            'gh api --method PATCH "/repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"',
        ):
            self.assertLess(global_gate, text.index(mutation), mutation)
        self.assertLess(
            text.index("inspect-http-etag"),
            text.index("assert-release-publish-nonclobber"),
        )
        self.assertLess(
            text.index("assert-release-publish-nonclobber"),
            text.index(
                'gh api --method PATCH "/repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"'
            ),
        )
        write = text.split("\n  write:", 1)[1].split("\n  release-readback:", 1)[0]
        checkout = write.split("- uses: actions/checkout@", 1)[1].split("- name:", 1)[0]
        self.assertIn("persist-credentials: false", checkout)
        self.assertLess(
            write.index("Re-download raw authorization bytes after approval"),
            write.index("assert-ghcr-nonclobber-write"),
        )
        self.assertLess(
            write.index("Revalidate candidate API bytes after approval"),
            write.index(
                "Extract the revalidated raw candidate artifact after approval"
            ),
        )
        self.assertLess(
            write.index(
                "Re-download and reverify all platform evidence after approval"
            ),
            write.index("assert-ghcr-nonclobber-write"),
        )
        self.assertLess(
            write.index("verify-platform-plan-binding"),
            write.index("assert-ghcr-nonclobber-write"),
        )
        self.assertLess(
            write.index("inspect-immutable-release-setting"),
            write.index("git push --atomic"),
        )
        oras_step = write.split("- name: Promote the canonical OCI layout", 1)[1].split(
            "- name:", 1
        )[0]
        self.assertLess(
            oras_step.index("inspect-ghcr-pages"),
            oras_step.index("cp --from-oci-layout"),
        )
        visibility_step = write.split("- name: Require exact GHCR package state", 1)[
            1
        ].split("- name:", 1)[0]
        self.assertLess(
            visibility_step.index("--required-state IDEMPOTENT_EXACT_IMAGE"),
            visibility_step.index('gh api --method PATCH "$update"'),
        )
        self.assertNotIn("state_artifact:", text)
        self.assertNotIn('grep -Fq "$OCI_MANIFEST_DIGEST"', text)
        self.assertNotIn("expected_policy_sha256:", text)
        self.assertNotIn("allowed_signers:", text.split("jobs:", 1)[0])
        for forbidden in (
            "cargo build",
            "docker build",
            "gh release create",
            "gh release upload",
            "docker push",
            "oras ",
            "skopeo ",
            "--clobber",
            "--force",
        ):
            self.assertNotIn(forbidden, text)

    def test_preflight_calls_real_existing_verifiers(self) -> None:
        text = self.WORKFLOW.read_text(encoding="utf-8")
        for invocation in (
            "scripts/candidate_manifest.py verify",
            "scripts/package_release.py verify",
            "scripts/oci_candidate.py verify",
            "scripts/external_authorization.py",
            "scripts/tag_promotion_attestation.py",
            "scripts/promotion_preflight.py inspect-remote-refs",
            "scripts/promotion_preflight.py inspect-platform-api",
            "scripts/promotion_preflight.py verify-platform-consumption",
        ):
            self.assertIn(invocation, text)
        helper = (self.ROOT / "scripts/promotion_preflight.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("platform_qualification.verify_artifact(args)", helper)


class PublicationPrimitiveTests(unittest.TestCase):
    VERSION = "0.2.0-alpha.1"
    SOURCE = "d" * 40
    AUTHORIZATION_ID = "e" * 64
    TAG_OID = "a" * 40
    MARKER_OID = "b" * 40
    OCI_DIGEST = "sha256:" + "c" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.asset = self.candidate / "asset.bin"
        self.asset.write_bytes(b"candidate bytes")
        digest = "sha256:" + hashlib.sha256(self.asset.read_bytes()).hexdigest()
        self.assets = [
            {"name": "asset.bin", "sha256": digest, "size": self.asset.stat().st_size}
        ]
        self.attestation_value = {
            "candidate": {
                "manifest_sha256": "sha256:" + "f" * 64,
                "source_sha": self.SOURCE,
                "version": self.VERSION,
            },
            "external_authorization": {
                "authorization": {"id": self.AUTHORIZATION_ID},
                "candidate": {
                    "commit": self.SOURCE,
                    "manifest_sha256": "sha256:" + "f" * 64,
                    "oci_manifest_digest": self.OCI_DIGEST,
                    "run_attempt": 1,
                    "run_id": 123,
                },
            },
            "kind": preflight.tag_promotion_attestation.KIND,
            "oci": {
                "manifest_sha256": self.OCI_DIGEST,
                "provenance_sha256": "sha256:" + "1" * 64,
            },
            "release_assets": self.assets,
            "schema_version": 1,
            "status": preflight.tag_promotion_attestation.STATUS,
            "tag": {
                "internal_name": f"v{self.VERSION}",
                "name": f"v{self.VERSION}",
                "object_sha": self.TAG_OID,
                "peeled_commit": self.SOURCE,
            },
        }
        self.attestation = self._json("attestation.json", self.attestation_value)
        platform_artifacts = []
        for index, spec in enumerate(
            preflight._platform_artifact_specs(1, self.SOURCE), start=1
        ):
            platform_artifacts.append(
                {
                    "archive_sha256": "sha256:" + f"{index:064x}",
                    "archive_size": index,
                    "artifact_id": index,
                    **spec,
                }
            )
        platform_identity = {
            "artifacts": platform_artifacts,
            "candidate": {
                "manifest_sha256": "sha256:" + "f" * 64,
                "oci_manifest_digest": self.OCI_DIGEST,
                "run_attempt": 1,
                "run_id": 123,
                "source_sha": self.SOURCE,
            },
            "kind": preflight.PLATFORM_INPUT_KIND,
            "project": {
                "repository": "owner/repo",
                "source_ref": "refs/heads/master",
                "source_sha": self.SOURCE,
            },
            "schema_version": 1,
            "status": preflight.platform_qualification.STATUS,
            "workflow": {
                "conclusion": "success",
                "path": preflight.PLATFORM_WORKFLOW_PATH,
                "run_attempt": 1,
                "run_id": 456,
            },
        }
        platform_rows = []
        for platform_id in preflight.PLATFORM_IDS:
            spec = preflight.platform_qualification.PLATFORMS[platform_id]
            platform_rows.append(
                {
                    "artifact": preflight._artifact_from_identity(
                        platform_identity, role="qualification", scope=platform_id
                    ),
                    "capture_sha256": "sha256:" + "2" * 64,
                    "engine": {
                        "context": spec.engine_context,
                        "os_type": "linux",
                        "provider": spec.provider,
                        "server_version": "1",
                        "version_output": "1",
                    },
                    "evidence": {"replay_count": 2},
                    "platform_id": platform_id,
                    "post_clean": {
                        "sha256": "sha256:" + "3" * 64,
                        "status": "EMPTY",
                    },
                    "readback": {
                        "artifact": preflight._artifact_from_identity(
                            platform_identity, role="readback", scope=platform_id
                        ),
                        "observation_sha256": "sha256:" + "4" * 64,
                    },
                    "record_sha256": "sha256:" + "5" * 64,
                    "runner": {
                        "arch": spec.runner_arch,
                        "environment": "self-hosted",
                        "os": spec.runner_os,
                    },
                }
            )
        self.platform_consumption = self.root / "platform-consumption.json"
        self.platform_consumption.write_bytes(
            preflight.canonical_bytes(
                {
                    "candidate_binding": {
                        "artifact": preflight._artifact_from_identity(
                            platform_identity,
                            role="candidate-binding",
                            scope="candidate",
                        ),
                        "observation_sha256": "sha256:" + "6" * 64,
                    },
                    "identity": platform_identity,
                    "kind": preflight.PLATFORM_CONSUMPTION_KIND,
                    "platforms": platform_rows,
                    "schema_version": 1,
                    "status": preflight.platform_qualification.STATUS,
                }
            )
        )
        marker_name = f"tomorrowci-authorization/{self.AUTHORIZATION_ID}"
        self.marker = self._json(
            "marker.json",
            {
                "internal_name": marker_name,
                "name": marker_name,
                "object_sha": self.MARKER_OID,
                "peeled_commit": self.SOURCE,
            },
        )
        version_ref = f"refs/tags/v{self.VERSION}"
        marker_ref = f"refs/tags/{marker_name}"
        self.remote = self._json(
            "remote.json",
            {
                "kind": preflight.KIND,
                "refs": {
                    marker_ref: self.MARKER_OID,
                    version_ref: self.TAG_OID,
                },
                "schema_version": 1,
                "state": "READY_FOR_ATOMIC_CREATE_ONLY",
                "status": preflight.DISABLED_STATUS,
            },
        )
        self.release_pages = self._pages("releases.json", [])
        self.version_pages = self._pages("versions.json", [])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _json(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def _pages(self, name: str, items: list[dict]) -> Path:
        return self._json(name, [items])

    def plan(self) -> tuple[dict, str]:
        return preflight.build_publication_plan(
            attestation_path=self.attestation,
            candidate_dir=self.candidate,
            remote_state_path=self.remote,
            marker_identity_path=self.marker,
            platform_consumption_path=self.platform_consumption,
            release_pages_path=self.release_pages,
            ghcr_versions_path=self.version_pages,
            repository="owner/repo",
        )

    def release(self, *, draft: bool, immutable: bool, assets: list[dict]) -> dict:
        body = preflight.release_body(
            self.attestation_value, oci_repository="ghcr.io/owner/tomorrowci"
        )
        return {
            "assets": assets,
            "body": body,
            "draft": draft,
            "id": 99,
            "immutable": immutable,
            "name": f"TomorrowCI v{self.VERSION}",
            "prerelease": True,
            "tag_name": f"v{self.VERSION}",
            "target_commitish": self.SOURCE,
        }

    def api_asset(self) -> dict:
        item = self.assets[0]
        return {"digest": item["sha256"], "name": item["name"], "size": item["size"]}

    def ghcr_version(self, digest: str, tags: list[str]) -> dict:
        return {
            "metadata": {"container": {"tags": tags}, "package_type": "container"},
            "name": digest,
        }

    def test_plan_is_exact_and_not_standalone_authority(self) -> None:
        plan, body = self.plan()
        self.assertEqual(plan["status"], preflight.DISABLED_STATUS)
        self.assertFalse(plan["mutation"]["plan_is_standalone_authority"])
        self.assertTrue(plan["mutation"]["protected_roll_forward"])
        self.assertEqual(plan["refs"]["atomic"], True)
        self.assertEqual(plan["refs"]["force"], False)
        self.assertEqual(plan["release"]["state"], "CREATE_NONCLOBBER_DRAFT_PRERELEASE")
        self.assertEqual(plan["ghcr"]["state"], "READY_FOR_EXACT_OCI_COPY")
        self.assertEqual(plan["ghcr"]["tool"], preflight.ORAS_TOOL)
        self.assertEqual(
            len(plan["platform_qualification"]["platforms"]),
            len(preflight.PLATFORM_IDS),
        )
        self.assertEqual(
            [item["name"] for item in plan["release"]["assets"]],
            ["asset.bin", "tag-promotion-attestation.json"],
        )
        self.assertIn(self.AUTHORIZATION_ID, body)
        self.assertIn(self.OCI_DIGEST, body)

    def test_candidate_drift_and_extra_file_fail_closed(self) -> None:
        self.asset.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes disagree"):
            self.plan()
        self.asset.write_bytes(b"candidate bytes")
        (self.candidate / "extra").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not equal"):
            self.plan()

    def test_platform_consumption_candidate_drift_fails_closed(self) -> None:
        consumption = json.loads(self.platform_consumption.read_text(encoding="utf-8"))
        consumption["identity"]["candidate"]["run_attempt"] = 2
        self.platform_consumption.write_bytes(preflight.canonical_bytes(consumption))
        with self.assertRaisesRegex(ValueError, "authorized candidate"):
            self.plan()

    def test_release_absent_partial_and_immutable_exact_states(self) -> None:
        body = preflight.release_body(
            self.attestation_value, oci_repository="ghcr.io/owner/tomorrowci"
        )
        absent = preflight.inspect_release_state(
            [],
            tag_name=f"v{self.VERSION}",
            target_commitish=self.SOURCE,
            release_name=f"TomorrowCI v{self.VERSION}",
            body=body,
            expected_assets=self.assets,
        )
        self.assertEqual(absent["state"], "CREATE_NONCLOBBER_DRAFT_PRERELEASE")
        partial = self.release(draft=True, immutable=False, assets=[])
        resumed = preflight.inspect_release_state(
            [partial],
            tag_name=f"v{self.VERSION}",
            target_commitish=self.SOURCE,
            release_name=f"TomorrowCI v{self.VERSION}",
            body=body,
            expected_assets=self.assets,
        )
        self.assertEqual(resumed["state"], "RESUME_EXACT_NONCLOBBER_DRAFT")
        published = self.release(draft=False, immutable=True, assets=[self.api_asset()])
        exact = preflight.inspect_release_state(
            [published],
            tag_name=f"v{self.VERSION}",
            target_commitish=self.SOURCE,
            release_name=f"TomorrowCI v{self.VERSION}",
            body=body,
            expected_assets=self.assets,
        )
        self.assertEqual(exact["state"], "IDEMPOTENT_EXACT_IMMUTABLE_PRERELEASE")
        published["target_commitish"] = "master"
        normalized = preflight.inspect_release_state(
            [published],
            tag_name=f"v{self.VERSION}",
            target_commitish=self.SOURCE,
            release_name=f"TomorrowCI v{self.VERSION}",
            body=body,
            expected_assets=self.assets,
        )
        self.assertEqual(normalized["state"], "IDEMPOTENT_EXACT_IMMUTABLE_PRERELEASE")

    def test_release_drift_and_mutable_publication_fail_closed(self) -> None:
        body = preflight.release_body(
            self.attestation_value, oci_repository="ghcr.io/owner/tomorrowci"
        )
        drift = self.release(draft=True, immutable=False, assets=[self.api_asset()])
        drift["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "bytes drift"):
            preflight.inspect_release_state(
                [drift],
                tag_name=f"v{self.VERSION}",
                target_commitish=self.SOURCE,
                release_name=f"TomorrowCI v{self.VERSION}",
                body=body,
                expected_assets=self.assets,
            )
        mutable = self.release(draft=False, immutable=False, assets=[self.api_asset()])
        with self.assertRaisesRegex(ValueError, "neither"):
            preflight.inspect_release_state(
                [mutable],
                tag_name=f"v{self.VERSION}",
                target_commitish=self.SOURCE,
                release_name=f"TomorrowCI v{self.VERSION}",
                body=body,
                expected_assets=self.assets,
            )

    def test_ghcr_exact_retry_and_drift_states(self) -> None:
        tag = f"v{self.VERSION}"
        self.assertEqual(
            preflight.inspect_ghcr_state(
                [], image_tag=tag, manifest_digest=self.OCI_DIGEST
            )["state"],
            "READY_FOR_EXACT_OCI_COPY",
        )
        present = [self.ghcr_version(self.OCI_DIGEST, [])]
        self.assertEqual(
            preflight.inspect_ghcr_state(
                present, image_tag=tag, manifest_digest=self.OCI_DIGEST
            )["state"],
            "READY_TO_ADD_EXACT_TAG",
        )
        exact = [self.ghcr_version(self.OCI_DIGEST, [tag])]
        self.assertEqual(
            preflight.inspect_ghcr_state(
                exact, image_tag=tag, manifest_digest=self.OCI_DIGEST
            )["state"],
            "IDEMPOTENT_EXACT_IMAGE",
        )
        wrong = [self.ghcr_version("sha256:" + "2" * 64, [tag])]
        with self.assertRaisesRegex(ValueError, "unrelated digest"):
            preflight.inspect_ghcr_state(
                wrong, image_tag=tag, manifest_digest=self.OCI_DIGEST
            )

    def test_ghcr_nonclobber_gap_is_explicitly_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "no proven create-only"):
            preflight.refuse_unconditional_ghcr_tag_write()

    def test_release_publish_without_if_match_is_explicitly_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "no conditional If-Match"):
            preflight.refuse_unconditional_release_publish()

    def test_prepared_state_extract_is_exact_and_fresh(self) -> None:
        source = self.root / "prepared"
        source.mkdir()
        for name in preflight.PREPARED_STATE_FILES:
            (source / name).write_bytes(f"{name}\n".encode())
        archive = self.root / "prepared.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for name in sorted(preflight.PREPARED_STATE_FILES):
                bundle.write(source / name, name)
        destination = self.root / "prepared-extracted"
        preflight.safe_extract_prepared_state(archive, destination)
        self.assertEqual(
            {entry.name for entry in destination.iterdir()},
            preflight.PREPARED_STATE_FILES,
        )
        with self.assertRaisesRegex(ValueError, "already exists"):
            preflight.safe_extract_prepared_state(archive, destination)
        bad = self.root / "bad-prepared.zip"
        with zipfile.ZipFile(bad, "w") as bundle:
            bundle.write(source / "publication-plan.json", "publication-plan.json")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            preflight.safe_extract_prepared_state(bad, self.root / "bad-extracted")

        nul_alias = self.root / "nul-prepared.zip"
        write_nul_suffixed_inventory(
            nul_alias,
            names=preflight.PREPARED_STATE_FILES,
            aliased_name="publication-plan.json",
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_prepared_state(
                nul_alias, self.root / "nul-prepared-extracted"
            )

    def test_candidate_extract_uses_only_the_verified_archive_inventory(self) -> None:
        source = self.root / "candidate-archive-source"
        source.mkdir()
        names = {
            *preflight.candidate_manifest.payload_names(self.VERSION),
            preflight.candidate_manifest.CHECKSUMS_NAME,
            preflight.candidate_manifest.MANIFEST_NAME,
        }
        for name in names:
            (source / name).write_bytes(f"{name}\n".encode())
        archive = self.root / "candidate.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for name in sorted(names):
                bundle.write(source / name, name)
        destination = self.root / "candidate-extracted"
        preflight.safe_extract_candidate(archive, destination, version=self.VERSION)
        self.assertEqual({entry.name for entry in destination.iterdir()}, names)

        bad = self.root / "candidate-extra.zip"
        with zipfile.ZipFile(bad, "w") as bundle:
            for name in sorted(names):
                bundle.write(source / name, name)
            bundle.writestr("unexpected", b"unexpected\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            preflight.safe_extract_candidate(
                bad, self.root / "candidate-extra-extracted", version=self.VERSION
            )

        nul_alias = self.root / "nul-candidate.zip"
        write_nul_suffixed_inventory(
            nul_alias,
            names=names,
            aliased_name=preflight.candidate_manifest.MANIFEST_NAME,
        )
        with self.assertRaisesRegex(ValueError, "unsafe"):
            preflight.safe_extract_candidate(
                nul_alias, self.root / "nul-candidate-extracted", version=self.VERSION
            )

    def test_release_environment_requires_independent_approval(self) -> None:
        environment = {
            "deployment_branch_policy": {
                "custom_branch_policies": False,
                "protected_branches": True,
            },
            "name": "release",
            "protection_rules": [
                {
                    "prevent_self_review": True,
                    "reviewers": [{"reviewer": {"id": 7}, "type": "User"}],
                    "type": "required_reviewers",
                }
            ],
        }
        preflight.inspect_release_environment(environment)
        changed = copy.deepcopy(environment)
        changed["protection_rules"][0]["prevent_self_review"] = False
        with self.assertRaisesRegex(ValueError, "reviewer approval"):
            preflight.inspect_release_environment(changed)

    def test_immutable_release_setting_is_explicit_and_fail_closed(self) -> None:
        preflight.inspect_immutable_release_setting({"enabled": True})
        for metadata in ({}, {"enabled": False}, {"enabled": 1}):
            with self.assertRaisesRegex(ValueError, "not enabled"):
                preflight.inspect_immutable_release_setting(metadata)

    def test_public_asset_and_oci_readback(self) -> None:
        downloaded = self.root / "downloaded"
        downloaded.mkdir()
        (downloaded / "asset.bin").write_bytes(b"candidate bytes")
        preflight.inspect_public_asset_readback(downloaded, self.assets)
        (downloaded / "asset.bin").write_bytes(b"drift")
        with self.assertRaisesRegex(ValueError, "read-back mismatch"):
            preflight.inspect_public_asset_readback(downloaded, self.assets)
        descriptor = self._json(
            "descriptor.json",
            {
                "digest": self.OCI_DIGEST,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 1551,
            },
        )
        preflight.inspect_public_oci_descriptor(descriptor, self.OCI_DIGEST)

    def test_etag_and_doctor_semantics_fail_closed(self) -> None:
        headers = self.root / "headers.txt"
        headers.write_bytes(b'HTTP/2 200\r\netag: W/"safe-123"\r\n\r\n')
        self.assertEqual(preflight.inspect_http_etag(headers), 'W/"safe-123"')
        headers.write_bytes(b'HTTP/2 200\r\netag: "one"\r\nETag: "two"\r\n\r\n')
        with self.assertRaisesRegex(ValueError, "single safe ETag"):
            preflight.inspect_http_etag(headers)
        doctor = self.root / "doctor.txt"
        doctor.write_text(
            "TomorrowCI doctor\n"
            f"tool_version: {self.VERSION}\n"
            "docker: false\n"
            "podman: false\n"
            "selected_engine: NONE (sandbox BLOCKED)\n"
            "security_defaults: OK\n"
            "host_execution_of_targets: FORBIDDEN by default\n"
            "status: BLOCKED for container execution\n",
            encoding="utf-8",
        )
        state = preflight.inspect_doctor_output(doctor, expected_version=self.VERSION)
        self.assertIn("BLOCKED", state["status"])
        doctor.write_text(
            doctor.read_text(encoding="utf-8").replace("docker: false", "docker: true"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "not honest"):
            preflight.inspect_doctor_output(doctor, expected_version=self.VERSION)

    def test_trust_and_package_snapshots_are_strict(self) -> None:
        packages = self._pages(
            "packages.json",
            [
                {
                    "name": "tomorrowci",
                    "owner": {"login": "owner"},
                    "package_type": "container",
                    "visibility": "public",
                }
            ],
        )
        self.assertEqual(
            preflight.inspect_package_pages(
                packages, package_name="tomorrowci", owner="owner"
            ),
            "PRESENT_PUBLIC",
        )


if __name__ == "__main__":
    unittest.main()
