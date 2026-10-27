#!/usr/bin/env python3
"""Importer contract regressions. These tests need neither Docker nor a registry."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import import_python_dependencies as importer


IMAGE = "python@sha256:" + "1" * 64


def make_wheel(directory: Path, name: str, version: str, *, payload: str = "value = 1\n",
               requires: tuple[str, ...] = (), metadata_name: str | None = None,
               wheel_tag: str = "py3-none-any",
               extra_members: dict[str, bytes | zipfile.ZipInfo] | None = None) -> Path:
    distribution = name.replace("-", "_")
    filename = f"{distribution}-{version}-{wheel_tag}.whl"
    path = directory / filename
    metadata = f"Metadata-Version: 2.1\nName: {metadata_name or name}\nVersion: {version}\n"
    metadata += "".join(f"Requires-Dist: {requirement}\n" for requirement in requires)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{distribution}.py", payload)
        archive.writestr(f"{distribution}-{version}.dist-info/METADATA", metadata + "\n")
        archive.writestr(f"{distribution}-{version}.dist-info/WHEEL",
                         f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {wheel_tag}\n\n")
        archive.writestr(f"{distribution}-{version}.dist-info/RECORD", "")
        for member, content in (extra_members or {}).items():
            if isinstance(content, zipfile.ZipInfo):
                archive.writestr(content, b"symlink-target")
            else:
                # ZipInfo's constructor normalizes backslashes on Windows;
                # preserve the deliberately malformed archive spelling here.
                info = zipfile.ZipInfo("placeholder")
                info.filename = member
                archive.writestr(info, content)
    return path


class PinTests(unittest.TestCase):
    def test_normalized_exact_pins_and_hash_continuations(self) -> None:
        sha = "a" * 64
        pins = importer.parse_pins(
            f"# a lock\nSome_Package==1.0 \\\n  --hash=sha256:{sha} # comment\n".encode(), "before", True
        )
        self.assertEqual(pins["some-package"].version, "1.0")
        self.assertEqual(pins["some-package"].hashes, ("sha256:" + sha,))

    def test_unsupported_requirement_semantics_are_rejected(self) -> None:
        for line in ("pkg>=1", "pkg==1.*", "pkg[extra]==1", "pkg==1; python_version>'3'",
                     "-r other.txt", "--index-url https://example.com", "pkg @ https://example.com/pkg.whl",
                     "-e .", "pkg==1 --trusted-host example.com"):
            with self.subTest(line=line), self.assertRaises(importer.ImportErrorDetail):
                importer.parse_pins((line + "\n").encode(), "before")

    def test_duplicate_names_partial_hashes_and_incomplete_continuation_fail(self) -> None:
        for raw in (b"Some_Package==1\nsome-package==2\n",
                    ("alpha==1 --hash=sha256:" + "a" * 64 + "\nbeta==2\n").encode(),
                    b"alpha==1 \\\n", b""):
            with self.subTest(raw=raw), self.assertRaises(importer.ImportErrorDetail):
                importer.parse_pins(raw, "before")
        with self.assertRaises(importer.ImportErrorDetail):
            importer.parse_pins(b"alpha==1\n", "before", require_hashes=True)


class ImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "checkout"
        self.target.mkdir()
        self.wheelhouse = self.root / "wheels"
        self.wheelhouse.mkdir()
        self.before = self.root / "before.txt"
        self.after = self.root / "after.txt"

    def import_pins(self, before: str, after: str, **kwargs: object) -> dict[str, object]:
        self.before.write_text(before, encoding="utf-8")
        self.after.write_text(after, encoding="utf-8")
        return importer.import_dependencies(target=self.target, before=self.before, after=self.after,
                                            runtime="3.11", image=IMAGE, wheelhouse=self.wheelhouse, **kwargs)

    def standard_wheels(self) -> None:
        make_wheel(self.wheelhouse, "alpha", "1.0", requires=("support>=1",))
        make_wheel(self.wheelhouse, "alpha", "2.0", requires=("support>=1",))
        make_wheel(self.wheelhouse, "support", "1.0")

    def test_real_artifact_delta_preserves_unchanged_closure_and_provenance(self) -> None:
        self.standard_wheels()
        result = self.import_pins("alpha==1.0\nsupport==1.0\n", "alpha==2.0\nsupport==1.0\n")
        manifest = json.loads(Path(result["manifest"]).read_text())
        provenance = json.loads(Path(result["provenance"]).read_text())
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["content_hash_algorithm"], "sha256-file-v1")
        self.assertEqual([item["name"] for item in manifest["candidate"]["changes"]], ["alpha"])
        self.assertEqual([item["name"] for item in manifest["unchanged"]], ["support"])
        self.assertEqual(provenance["mode"], "offline-wheelhouse")
        self.assertIn("NOT_RUN", provenance["scope"]["compatibility"])
        self.assertEqual(provenance["manifest_sha256"], importer.digest(Path(result["manifest"]).read_bytes()))
        self.assertEqual(len(provenance["artifacts"]), 3)
        for item in provenance["artifacts"]:
            self.assertEqual(item["content_sha256"], importer.digest((self.target / item["source"]).read_bytes()))
            self.assertIsNone(item["source_url"])
        self.assertFalse((self.target / ".tomorrowci-import.lock").exists())

    def test_import_does_not_execute_wheel_payload_or_claim_closure_was_validated(self) -> None:
        marker = self.root / "must-not-exist"
        payload = f"raise RuntimeError({str(marker)!r})\n"
        make_wheel(self.wheelhouse, "alpha", "1.0", payload=payload, requires=("missing>=1",))
        make_wheel(self.wheelhouse, "alpha", "2.0", payload=payload, requires=("missing>=2",))
        with patch.object(importer.subprocess, "run", side_effect=AssertionError("offline import invoked a process")):
            result = self.import_pins("alpha==1.0\n", "alpha==2.0\n")
        self.assertFalse(marker.exists())
        provenance = json.loads(Path(result["provenance"]).read_text())
        self.assertIn("each probe validates", provenance["scope"]["closure"])
        self.assertEqual({tuple(item["requires_dist"]) for item in provenance["artifacts"]},
                         {("missing>=1",), ("missing>=2",)})

    def test_missing_wheels_and_additions_removals_fail_before_publication(self) -> None:
        make_wheel(self.wheelhouse, "alpha", "1.0")
        for before, after in (("alpha==1.0\n", "alpha==2.0\n"),
                              ("alpha==1.0\n", "alpha==1.0\nbeta==2.0\n"),
                              ("alpha==1.0\nbeta==2.0\n", "alpha==1.0\n")):
            with self.subTest(after=after), self.assertRaises(importer.ImportErrorDetail):
                self.import_pins(before, after)
            self.assertFalse((self.target / importer.MANIFEST).exists())
            self.assertFalse((self.target / "vendor").exists())

    def test_no_change_and_more_than_64_changes_are_rejected(self) -> None:
        make_wheel(self.wheelhouse, "alpha", "1.0")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "actual artifact updates"):
            self.import_pins("alpha==1.0\n", "alpha==1.0\n")
        with patch.object(importer, "MAX_CHANGES", 1):
            make_wheel(self.wheelhouse, "alpha", "2.0")
            make_wheel(self.wheelhouse, "beta", "1.0")
            make_wheel(self.wheelhouse, "beta", "2.0")
            with self.assertRaisesRegex(importer.ImportErrorDetail, "actual artifact updates"):
                self.import_pins("alpha==1.0\nbeta==1.0\n", "alpha==2.0\nbeta==2.0\n")

    def test_existing_manifest_output_and_lock_are_not_overwritten(self) -> None:
        self.standard_wheels()
        manifest = self.target / importer.MANIFEST
        manifest.write_bytes(b"user manifest")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "overwrite"):
            self.import_pins("alpha==1.0\n", "alpha==2.0\n")
        self.assertEqual(manifest.read_bytes(), b"user manifest")
        manifest.unlink()
        output = self.target / "vendor" / "python-dependencies"
        output.mkdir(parents=True)
        (output / "user.txt").write_text("user data")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "already exists"):
            self.import_pins("alpha==1.0\n", "alpha==2.0\n")
        self.assertEqual((output / "user.txt").read_text(), "user data")
        lock = self.target / ".tomorrowci-import.lock"
        lock.write_bytes(b"someone else")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "retained import lock"):
            self.import_pins("alpha==1.0\n", "alpha==2.0\n", output_dir="other-output")
        self.assertEqual(lock.read_bytes(), b"someone else")

    def test_manifest_commit_is_exclusive_even_after_preflight(self) -> None:
        self.standard_wheels()
        original_link = os.link
        def race(source: object, destination: object) -> None:
            Path(destination).write_bytes(b"concurrent user manifest")
            original_link(source, destination)
        with patch.object(importer.os, "link", side_effect=race):
            with self.assertRaisesRegex(importer.ImportErrorDetail, "without overwriting"):
                self.import_pins("alpha==1.0\n", "alpha==2.0\n")
        self.assertEqual((self.target / importer.MANIFEST).read_bytes(), b"concurrent user manifest")

    def test_hash_lock_is_verified_and_reported(self) -> None:
        first = make_wheel(self.wheelhouse, "alpha", "1.0")
        second = make_wheel(self.wheelhouse, "alpha", "2.0")
        before = "alpha==1.0 --hash=" + importer.digest(first.read_bytes()) + "\n"
        after = "alpha==2.0 --hash=" + importer.digest(second.read_bytes()) + "\n"
        result = self.import_pins(before, after, require_hashes=True)
        self.assertEqual(json.loads(Path(result["provenance"]).read_text())["hash_locked"],
                         {"before": True, "after": True})

    def test_wrong_hash_and_metadata_identity_are_rejected(self) -> None:
        first = make_wheel(self.wheelhouse, "alpha", "1.0")
        make_wheel(self.wheelhouse, "alpha", "2.0")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "hash lock"):
            self.import_pins("alpha==1.0 --hash=sha256:" + "f" * 64 + "\n", "alpha==2.0\n")
        first.unlink()
        make_wheel(self.wheelhouse, "alpha", "1.0", metadata_name="some-other-package")
        with self.assertRaisesRegex(importer.ImportErrorDetail, "identity disagree"):
            self.import_pins("alpha==1.0\n", "alpha==2.0\n")

    def test_direct_reference_dependencies_are_rejected_before_publication(self) -> None:
        make_wheel(self.wheelhouse, "alpha", "1.0")
        for reference in ("hidden @ https://example.com/hidden.whl",
                          "hidden @ file:///work/unselected/hidden.whl"):
            with self.subTest(reference=reference):
                make_wheel(self.wheelhouse, "alpha", "2.0", requires=(reference,))
                with self.assertRaisesRegex(importer.ImportErrorDetail, "direct-reference Requires-Dist"):
                    self.import_pins("alpha==1.0\n", "alpha==2.0\n")
                self.assertFalse((self.target / importer.MANIFEST).exists())
                self.assertFalse((self.target / "vendor").exists())

    def test_ambiguous_wheel_selection_is_rejected(self) -> None:
        original = make_wheel(self.wheelhouse, "alpha", "1.0")
        (self.wheelhouse / "alpha-1.0-1-py3-none-any.whl").write_bytes(original.read_bytes())
        with self.assertRaisesRegex(importer.ImportErrorDetail, "ambiguous wheels"):
            importer.select_wheels(self.wheelhouse, {"alpha": importer.Pin("alpha", "1.0")})

    def test_same_version_repacked_wheel_is_rejected(self) -> None:
        old_path = make_wheel(self.wheelhouse, "alpha", "1.0", payload="value = 1\n")
        other = self.root / "other-wheels"
        other.mkdir()
        new_path = make_wheel(other, "alpha", "1.0", payload="value = 2\n")
        snapshots = [{"alpha": importer.inspect_wheel(old_path)}, {"alpha": importer.inspect_wheel(new_path)}]
        with patch.object(importer, "select_wheels", side_effect=snapshots):
            with self.assertRaisesRegex(importer.ImportErrorDetail, "same-version artifact replacement"):
                self.import_pins("alpha==1.0\n", "alpha==1.0\n")
        self.assertFalse((self.target / importer.MANIFEST).exists())

    def test_unsafe_zip_members_links_and_metadata_limits_are_rejected(self) -> None:
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for members in ({"../escape.py": b"bad"}, {"/absolute.py": b"bad"},
                        {"dir\\escape.py": b"bad"}, {"link": symlink},
                        {"alpha-1.0.dist-info/metadata": b"duplicate by case"}):
            with self.subTest(members=members):
                wheel = make_wheel(self.wheelhouse, "alpha", "1.0", extra_members=members)
                with self.assertRaises(importer.ImportErrorDetail):
                    importer.inspect_wheel(wheel)
        wheel = make_wheel(self.wheelhouse, "alpha", "1.0")
        with patch.object(importer, "MAX_METADATA_BYTES", 10):
            with self.assertRaisesRegex(importer.ImportErrorDetail, "metadata exceeds"):
                importer.inspect_wheel(wheel)

    def test_output_path_cannot_escape_or_hide_from_workspace_snapshot(self) -> None:
        self.standard_wheels()
        for relative in ("../escape", "/absolute", "vendor//new", "vendor\\new", ".git/assets",
                         ".tomorrowci/assets", "vendor/../new", "C:/absolute"):
            with self.subTest(relative=relative), self.assertRaises(importer.ImportErrorDetail):
                self.import_pins("alpha==1.0\n", "alpha==2.0\n", output_dir=relative)

    def test_source_changed_after_inspection_is_rejected(self) -> None:
        self.standard_wheels()
        original = importer.select_wheels
        calls = 0
        def select(directory: Path, pins: dict[str, importer.Pin]) -> dict[str, importer.Wheel]:
            nonlocal calls
            result = original(directory, pins)
            calls += 1
            if calls == 2:
                (self.wheelhouse / "alpha-1.0-py3-none-any.whl").write_bytes(b"changed")
            return result
        with patch.object(importer, "select_wheels", side_effect=select):
            with self.assertRaisesRegex(importer.ImportErrorDetail, "changed after inspection"):
                self.import_pins("alpha==1.0\n", "alpha==2.0\n")
        self.assertFalse((self.target / importer.MANIFEST).exists())

    def test_long_native_wheel_names_use_flat_paths_in_a_nested_checkout(self) -> None:
        self.target = self.root / ("checkout-" + "x" * 48)
        self.target.mkdir()
        tag = "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64"
        first = make_wheel(self.wheelhouse, "MarkupSafe", "2.0.1", wheel_tag=tag)
        second = make_wheel(self.wheelhouse, "MarkupSafe", "2.1.3", wheel_tag=tag)
        result = self.import_pins("MarkupSafe==2.0.1\n", "MarkupSafe==2.1.3\n")
        manifest = json.loads(Path(result["manifest"]).read_text())
        change = manifest["candidate"]["changes"][0]
        for label, original in (("before", first), ("after", second)):
            artifact = change[label]
            self.assertEqual(artifact["source"], "vendor/python-dependencies/wheels/" + original.name)
            self.assertEqual((self.target / artifact["source"]).read_bytes(), original.read_bytes())
            self.assertEqual(artifact["content_sha256"], importer.digest(original.read_bytes()))


class DownloadContractTests(unittest.TestCase):
    def test_download_container_cannot_execute_sdists_or_access_checkout_secrets(self) -> None:
        command = importer.docker_download_command(Path("/task/inputs"), Path("/task/output"),
                                                    IMAGE, "3.11", "before.txt", "test-container")
        self.assertIn("--network=bridge", command)
        self.assertIn("--read-only", command)
        self.assertIn("--user=65534:65534", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--pids-limit=128", command)
        mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
        self.assertEqual(mounts, [f"type=bind,source={Path('/task/inputs')},target=/inputs,readonly",
                                  f"type=bind,source={Path('/task/output')},target=/out"])
        self.assertNotIn("docker.sock", " ".join(command))
        self.assertIn('"--only-binary=:all:"', importer.DOWNLOAD_PROGRAM)
        self.assertIn('"--no-deps"', importer.DOWNLOAD_PROGRAM)
        self.assertIn('"https://pypi.org/simple"', importer.DOWNLOAD_PROGRAM)
        self.assertIn("pinned image runtime mismatch", importer.DOWNLOAD_PROGRAM)

    def test_download_timeout_cleans_only_the_owned_container(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []
            def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append(command)
                if command[1] == "run":
                    raise subprocess.TimeoutExpired(command, 1)
                return subprocess.CompletedProcess(command, 0, b"", b"")
            with patch.object(importer.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(importer.ImportErrorDetail, "cleanup requested"):
                    importer.download_wheels(root, root / "out", IMAGE, "3.11", "before.txt", 1)
            name = calls[0][calls[0].index("--name") + 1]
            self.assertTrue(name.startswith("tomorrowci-import-"))
            self.assertEqual(calls[1], ["docker", "rm", "--force", name])

    def test_saved_source_urls_strip_credentials_queries_and_fragments(self) -> None:
        log = "Downloading https://user:secret@example.com/files/alpha-1.0-py3-none-any.whl?token=secret#x"
        sanitized = importer.redact_urls(log)
        self.assertNotIn("secret", sanitized)
        self.assertEqual(importer.source_urls([sanitized]),
                         {"alpha-1.0-py3-none-any.whl": "https://example.com/files/alpha-1.0-py3-none-any.whl"})


if __name__ == "__main__":
    unittest.main()
