#!/usr/bin/env python3
"""Import exact Python pin snapshots as an offline, wheel-backed experiment.

This does not execute package code or claim dependency compatibility. Download
selection runs in the pinned container; each scan probe must install its complete
selected wheel set offline, with dependency checking enabled.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import compat32
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit
import uuid
import zipfile


MANIFEST = ".tomorrowci-dependencies.json"
MAX_LOCK_BYTES = 256 * 1024
MAX_PACKAGES = 256
MAX_CHANGES = 64
MAX_WHEEL_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_ZIP_MEMBERS = 10000
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PIN = re.compile(rf"^({NAME})\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(.*)$")
IMAGE = re.compile(r"^[a-z0-9]+(?:[._/:\-][a-z0-9]+)*@sha256:[0-9a-f]{64}$")
URL = re.compile(r"https?://[^\s<>\"']+")


class ImportErrorDetail(RuntimeError):
    """An unsupported or inconsistent import; never a compatibility verdict."""


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    hashes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Wheel:
    path: Path
    name: str
    version: str
    content_sha256: str
    size: int
    requires_dist: tuple[str, ...]
    requires_python: str | None
    tags: tuple[str, ...]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def normalized_name(value: str) -> str:
    if not re.fullmatch(NAME, value):
        raise ImportErrorDetail(f"invalid distribution name: {value!r}")
    return re.sub(r"[-_.]+", "-", value).lower()


def is_alias(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def plain_file(path: Path, limit: int) -> bytes:
    if is_alias(path) or not path.is_file() or path.stat().st_size > limit:
        raise ImportErrorDetail(f"expected a bounded plain file (maximum {limit} bytes): {path}")
    with path.open("rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ImportErrorDetail(f"file grew past its size limit: {path}")
    return value


def parse_pins(raw: bytes, label: str, require_hashes: bool = False) -> dict[str, Pin]:
    if len(raw) > MAX_LOCK_BYTES:
        raise ImportErrorDetail(f"{label}: pin snapshot exceeds {MAX_LOCK_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as error:
        raise ImportErrorDetail(f"{label}: pin snapshot must be UTF-8") from error
    logical: list[tuple[int, str]] = []
    pending = ""
    first_line = 0
    for number, physical in enumerate(text.splitlines(), 1):
        line = physical.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        if not pending:
            first_line = number
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        logical.append((first_line, pending + line))
        pending = ""
    if pending:
        raise ImportErrorDetail(f"{label}: incomplete line continuation")
    pins: dict[str, Pin] = {}
    for number, line in logical:
        match = PIN.fullmatch(line)
        if match is None:
            raise ImportErrorDetail(
                f"{label}:{number}: require name==version; extras, markers, URLs, editable, "
                "includes, ranges and pip options are unsupported"
            )
        name, version, suffix = match.groups()
        name = normalized_name(name)
        hashes = []
        for option in suffix.split():
            if not re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", option):
                raise ImportErrorDetail(f"{label}:{number}: only SHA256 --hash options are supported")
            hashes.append(option.removeprefix("--hash="))
        if name in pins:
            raise ImportErrorDetail(f"{label}:{number}: repeated normalized distribution {name}")
        pins[name] = Pin(name, version, tuple(sorted(set(hashes))))
    if not pins or len(pins) > MAX_PACKAGES:
        raise ImportErrorDetail(f"{label}: require between 1 and {MAX_PACKAGES} complete pins")
    if (require_hashes or any(pin.hashes for pin in pins.values())) and any(
        not pin.hashes for pin in pins.values()
    ):
        raise ImportErrorDetail(f"{label}: hash-lock mode requires SHA256 hashes for every pin")
    return pins


def canonical_pins(pins: dict[str, Pin]) -> bytes:
    return "".join(
        f"{pin.name}=={pin.version}"
        + "".join(f" --hash={value}" for value in pin.hashes)
        + "\n"
        for _, pin in sorted(pins.items())
    ).encode("utf-8")


def wheel_filename(path: Path) -> tuple[str, str]:
    if not path.name.endswith(".whl") or not re.fullmatch(r"[A-Za-z0-9_.+!\-]+\.whl", path.name):
        raise ImportErrorDetail(f"unsupported wheel filename: {path.name}")
    fields = path.name[:-4].split("-")
    if len(fields) not in (5, 6) or not all(fields):
        raise ImportErrorDetail(f"malformed wheel filename: {path.name}")
    if len(fields) == 6 and not fields[2][0].isdigit():
        raise ImportErrorDetail(f"malformed wheel build tag: {path.name}")
    return normalized_name(fields[0]), fields[1]


def inspect_wheel(path: Path) -> Wheel:
    filename_name, filename_version = wheel_filename(path)
    raw = plain_file(path, MAX_WHEEL_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_MEMBERS or sum(item.file_size for item in entries) > MAX_UNPACKED_BYTES:
                raise ImportErrorDetail(f"wheel exceeds archive limits: {path.name}")
            seen: set[str] = set()
            for item in entries:
                # ZipInfo normalizes host separators and truncates at NUL.
                # Validate the recorded ZIP spelling before accepting that view.
                name = item.orig_filename
                parts = name.rstrip("/").split("/")
                mode = item.external_attr >> 16
                if (
                    name != item.filename or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in ("", ".", "..") for part in parts)
                    or name.casefold() in seen or item.flag_bits & 1
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                ):
                    raise ImportErrorDetail(f"unsafe, duplicate or encrypted wheel member: {path.name}: {name!r}")
                seen.add(name.casefold())
            metadata_entries = [
                item for item in entries
                if len(item.filename.split("/")) == 2
                and item.filename.split("/")[0].endswith(".dist-info")
                and item.filename.endswith("/METADATA")
            ]
            if len(metadata_entries) != 1:
                raise ImportErrorDetail(f"wheel needs exactly one top-level dist-info/METADATA: {path.name}")
            metadata_entry = metadata_entries[0]
            wheel_name = metadata_entry.filename.removesuffix("METADATA") + "WHEEL"
            try:
                wheel_entry = archive.getinfo(wheel_name)
            except KeyError as error:
                raise ImportErrorDetail(f"wheel lacks matching WHEEL metadata: {path.name}") from error
            if any(item.file_size > MAX_METADATA_BYTES for item in (metadata_entry, wheel_entry)):
                raise ImportErrorDetail(f"wheel metadata exceeds {MAX_METADATA_BYTES} bytes: {path.name}")
            metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_entry), headersonly=True)
            wheel_metadata = BytesParser(policy=compat32).parsebytes(archive.read(wheel_entry), headersonly=True)
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ImportErrorDetail(f"cannot inspect wheel {path.name}: {error}") from error
    names = metadata.get_all("Name", [])
    versions = metadata.get_all("Version", [])
    if metadata.defects or len(names) != 1 or len(versions) != 1:
        raise ImportErrorDetail(f"wheel needs unambiguous Name and Version metadata: {path.name}")
    name, version = normalized_name(str(names[0]).strip()), str(versions[0]).strip()
    if (name, version) != (filename_name, filename_version):
        raise ImportErrorDetail(f"wheel filename and METADATA identity disagree: {path.name}")
    expected_dist_info = path.name[:-4].split("-")[0] + "-" + filename_version + ".dist-info"
    if metadata_entry.filename.split("/")[0] != expected_dist_info:
        raise ImportErrorDetail(f"wheel dist-info directory identity disagrees: {path.name}")
    if wheel_metadata.defects or wheel_metadata.get_all("Wheel-Version", []) != ["1.0"]:
        raise ImportErrorDetail(f"only Wheel-Version 1.0 is supported: {path.name}")
    tags = tuple(str(tag).strip() for tag in wheel_metadata.get_all("Tag", []))
    if not tags or any(not re.fullmatch(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", tag) for tag in tags):
        raise ImportErrorDetail(f"wheel needs valid compatibility tags: {path.name}")
    requires_dist = tuple(str(value).strip() for value in metadata.get_all("Requires-Dist", []))
    if any("@" in value for value in requires_dist):
        raise ImportErrorDetail(
            f"direct-reference Requires-Dist is unsupported (including HTTP and file URLs): {path.name}"
        )
    requires_python = metadata.get_all("Requires-Python", [])
    if len(requires_python) > 1 or any("\x00" in value for value in (*requires_dist, *requires_python)):
        raise ImportErrorDetail(f"ambiguous or malformed dependency metadata: {path.name}")
    # Hash again when copying into staging; this is inspection, not extraction.
    return Wheel(path, name, version, digest(raw), len(raw), requires_dist,
                 str(requires_python[0]) if requires_python else None, tags)


def select_wheels(directory: Path, pins: dict[str, Pin]) -> dict[str, Wheel]:
    if is_alias(directory) or not directory.is_dir():
        raise ImportErrorDetail(f"wheelhouse must be a plain directory: {directory}")
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    if len(entries) > 2 * MAX_PACKAGES:
        raise ImportErrorDetail("wheelhouse has too many entries; provide a bounded, flat wheel snapshot")
    selected: dict[str, Wheel] = {}
    for path in entries:
        if path.suffix != ".whl":
            continue
        name, version = wheel_filename(path)
        pin = pins.get(name)
        if pin is None or pin.version != version:
            continue
        artifact = inspect_wheel(path)
        if pin.hashes and artifact.content_sha256 not in pin.hashes:
            raise ImportErrorDetail(f"wheel does not match the input hash lock: {name}=={version}")
        if name in selected:
            raise ImportErrorDetail(f"ambiguous wheels for {name}=={version}; provide one selected artifact")
        selected[name] = artifact
    missing = sorted(set(pins) - set(selected))
    if missing:
        raise ImportErrorDetail("missing exact wheels for: " + ", ".join(missing))
    if sum(item.size for item in selected.values()) > MAX_TOTAL_BYTES:
        raise ImportErrorDetail(f"selected wheel set exceeds {MAX_TOTAL_BYTES} bytes")
    return selected


def redact_urls(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            parsed = urlsplit(match.group())
            host = parsed.hostname or "redacted"
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
        except ValueError:
            return "[redacted-url]"
    return URL.sub(replace, text)


# No project/package code runs here. pip selects/downloads binary archives only.
DOWNLOAD_PROGRAM = r'''
import os, pathlib, shutil, subprocess, sys
expected, lock_name = sys.argv[1:]
actual = f"{sys.version_info.major}.{sys.version_info.minor}"
if actual != expected:
    raise SystemExit(f"pinned image runtime mismatch: expected {expected}, observed {actual}")
print(f"Python runtime: {sys.version.split()[0]}", flush=True)
subprocess.run([sys.executable, "-m", "pip", "--version"], check=True)
destination = pathlib.Path("/tmp/wheels")
destination.mkdir()
download = subprocess.run([
    sys.executable, "-m", "pip", "--isolated", "download", "--verbose",
    "--disable-pip-version-check", "--no-cache-dir", "--only-binary=:all:",
    "--no-deps", "--index-url", "https://pypi.org/simple", "--timeout", "30",
    "--retries", "1", "--dest", str(destination), "--requirement", "/inputs/" + lock_name
], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
if len(download.stdout) > 4194304:
    raise SystemExit("download log exceeded import limit")
sys.stdout.buffer.write(download.stdout)
sys.stdout.buffer.flush()
if download.returncode:
    raise SystemExit(download.returncode)
files = list(destination.iterdir())
if len(files) > 256 or sum(item.stat().st_size for item in files) > 536870912:
    raise SystemExit("downloaded wheel set exceeds import limits")
for item in files:
    if not item.is_file() or item.is_symlink() or item.suffix != ".whl" or item.stat().st_size > 134217728:
        raise SystemExit("download did not produce bounded plain wheels")
    shutil.copyfile(item, pathlib.Path("/out") / item.name)
'''


def docker_download_command(input_dir: Path, output_dir: Path, image: str, runtime: str,
                            lock_name: str, container_name: str) -> list[str]:
    for path in (input_dir, output_dir):
        if "," in str(path) or "\n" in str(path):
            raise ImportErrorDetail("Docker bind paths cannot contain commas or newlines")
    return [
        "docker", "run", "--rm", "--pull=never", "--name", container_name,
        "--network=bridge", "--read-only", "--user=65534:65534",
        "--memory=1024m", "--cpus=1", "--pids-limit=128", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=768m,mode=1777",
        "--mount", f"type=bind,source={input_dir},target=/inputs,readonly",
        "--mount", f"type=bind,source={output_dir},target=/out",
        "--env", "HOME=/tmp", "--env", "PIP_CONFIG_FILE=/dev/null",
        "--entrypoint", "python", image, "-c", DOWNLOAD_PROGRAM, runtime, lock_name,
    ]


def download_wheels(input_dir: Path, output_dir: Path, image: str, runtime: str,
                    lock_name: str, timeout: int) -> str:
    output_dir.mkdir()
    output_dir.chmod(0o777)
    name = "tomorrowci-import-" + uuid.uuid4().hex
    command = docker_download_command(input_dir, output_dir, image, runtime, lock_name, name)
    # Only this invocation's named container may be cleaned up on timeout.
    try:
        process = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        try:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
        raise ImportErrorDetail(f"wheel download exceeded {timeout} seconds; container {name} cleanup requested") from error
    except OSError as error:
        raise ImportErrorDetail(f"cannot launch Docker wheel download: {error}") from error
    output = process.stdout + process.stderr
    if len(output) > MAX_LOG_BYTES:
        raise ImportErrorDetail("download log exceeded the bounded import log limit")
    log = redact_urls(output.decode("utf-8", errors="replace"))
    if process.returncode:
        raise ImportErrorDetail(
            f"wheel download failed (exit {process.returncode}); load the pinned image locally first if absent:\n{log}"
        )
    return log


def source_urls(logs: list[str]) -> dict[str, str]:
    candidates: dict[str, set[str]] = {}
    for log in logs:
        for match in URL.finditer(log):
            safe = redact_urls(match.group()).rstrip(").,")
            path = urlsplit(safe).path
            if path.endswith(".whl"):
                candidates.setdefault(unquote(path.rsplit("/", 1)[-1]), set()).add(safe)
    return {name: next(iter(urls)) for name, urls in candidates.items() if len(urls) == 1}


def validate_output(target: Path, relative: str) -> Path:
    parts = relative.split("/")
    if (not relative or "\\" in relative or ":" in relative
            or any(part in ("", ".", "..") for part in parts)
            or any(part.casefold() in (".git", ".tomorrowci") for part in parts)):
        raise ImportErrorDetail("output-dir must be a canonical workspace-relative directory outside .git/.tomorrowci")
    current = target
    for part in parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if is_alias(current) or not current.is_dir():
                raise ImportErrorDetail(f"output parent must be a plain directory: {current}")
    if current.exists():
        raise ImportErrorDetail(f"output directory already exists; choose a new path: {current}")
    return current


def import_dependencies(*, target: Path, before: Path, after: Path, runtime: str, image: str,
                        output_dir: str = "vendor/python-dependencies", wheelhouse: Path | None = None,
                        timeout_seconds: int = 300, require_hashes: bool = False) -> dict[str, Any]:
    target = target.absolute()
    if is_alias(target) or not target.is_dir():
        raise ImportErrorDetail("target must be an existing plain checkout directory")
    target = target.resolve(strict=True)
    if not re.fullmatch(r"3\.(?:[1-9][0-9]*)", runtime) or not IMAGE.fullmatch(image):
        raise ImportErrorDetail("require canonical Python 3.minor and an immutable image@sha256 digest")
    if not 1 <= timeout_seconds <= 1800:
        raise ImportErrorDetail("timeout-seconds must be between 1 and 1800")
    manifest_path = target / MANIFEST
    if manifest_path.exists() or manifest_path.is_symlink():
        raise ImportErrorDetail(f"refusing to overwrite existing {MANIFEST}")
    destination = validate_output(target, output_dir)
    raw_inputs = [plain_file(before, MAX_LOCK_BYTES), plain_file(after, MAX_LOCK_BYTES)]
    pin_sets = [parse_pins(raw, label, require_hashes) for raw, label in zip(raw_inputs, ("before", "after"))]
    if set(pin_sets[0]) != set(pin_sets[1]):
        added = sorted(set(pin_sets[1]) - set(pin_sets[0]))
        removed = sorted(set(pin_sets[0]) - set(pin_sets[1]))
        raise ImportErrorDetail(f"additions/removals are unsupported: added={added}, removed={removed}")
    lock_path = target / ".tomorrowci-import.lock"
    try:
        lock = lock_path.open("xb")
    except FileExistsError as error:
        raise ImportErrorDetail("another import or a retained import lock exists; refusing concurrent publication") from error
    with lock:
        lock.write(b"exclusive Python dependency import\n")
    published_directory = False
    try:
        with tempfile.TemporaryDirectory(prefix=".tomorrowci-import-", dir=target) as temporary:
            stage = Path(temporary)
            stage.chmod(0o755)
            inputs = stage / "inputs"
            inputs.mkdir()
            for label, pins in zip(("before", "after"), pin_sets):
                (inputs / f"{label}.txt").write_bytes(canonical_pins(pins))
            logs = []
            wheels = []
            for label, pins in zip(("before", "after"), pin_sets):
                if wheelhouse is None:
                    directory = stage / (label + "-download")
                    log = download_wheels(inputs, directory, image, runtime, f"{label}.txt", timeout_seconds)
                else:
                    if is_alias(wheelhouse):
                        raise ImportErrorDetail("wheelhouse cannot be a symlink/reparse directory")
                    directory = wheelhouse.resolve(strict=True)
                    log = "Offline wheel snapshot supplied; compatibility is checked by probe installation.\n"
                logs.append(log)
                wheels.append(select_wheels(directory, pins))
            urls = source_urls(logs)
            payload = stage / "payload"
            payload.mkdir()
            artifacts: dict[str, dict[str, Any]] = {}
            total_bytes = 0

            def declaration(wheel: Wheel) -> dict[str, str]:
                nonlocal total_bytes
                # Keep the original wheel filename (required by pip), without a
                # 64-character hash directory that exhausts Windows path limits.
                # Full byte identities remain bound in manifest and provenance.
                relative = f"wheels/{wheel.path.name}"
                if relative in artifacts and artifacts[relative]["content_sha256"] != wheel.content_sha256:
                    raise ImportErrorDetail(f"conflicting wheel bytes share a filename: {wheel.path.name}")
                if relative not in artifacts:
                    raw = plain_file(wheel.path, MAX_WHEEL_BYTES)
                    if digest(raw) != wheel.content_sha256:
                        raise ImportErrorDetail(f"wheel changed after inspection: {wheel.path.name}")
                    total_bytes += len(raw)
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise ImportErrorDetail("combined before/after artifact snapshot exceeds import byte budget")
                    copied = payload / relative
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    copied.write_bytes(raw)
                    artifacts[relative] = {
                        "name": wheel.name, "version": wheel.version, "filename": wheel.path.name,
                        "source": f"{output_dir}/{relative}", "content_sha256": wheel.content_sha256,
                        "size_bytes": wheel.size, "requires_dist": list(wheel.requires_dist),
                        "requires_python": wheel.requires_python, "wheel_tags": list(wheel.tags),
                        "source_url": urls.get(wheel.path.name),
                    }
                return {"version": wheel.version, "source": f"{output_dir}/{relative}",
                        "content_sha256": wheel.content_sha256}

            changes = []
            unchanged = []
            for name in sorted(pin_sets[0]):
                previous, following = wheels[0][name], wheels[1][name]
                if previous.version == following.version and previous.content_sha256 != following.content_sha256:
                    raise ImportErrorDetail(f"same-version artifact replacement is unsupported: {name}=={previous.version}")
                old, new = declaration(previous), declaration(following)
                if old == new:
                    unchanged.append({"id": name, "name": name, "artifact": old})
                else:
                    changes.append({"id": name, "name": name, "before": old, "after": new})
            if not 1 <= len(changes) <= MAX_CHANGES:
                raise ImportErrorDetail(f"require 1 to {MAX_CHANGES} actual artifact updates; found {len(changes)}")
            identity = digest(canonical_json({"before": canonical_pins(pin_sets[0]).decode(),
                                               "after": canonical_pins(pin_sets[1]).decode()}))[7:19]
            manifest = {
                "schema_version": 2, "ecosystem": "python",
                "runtime": {"version": runtime, "container_image": image},
                "content_hash_algorithm": "sha256-file-v1",
                "baseline": {"set_id": "python-before-" + identity},
                "candidate": {"set_id": "python-after-" + identity, "changes": changes},
                "unchanged": unchanged,
            }
            manifest_bytes = canonical_json(manifest)
            for index, label in enumerate(("before", "after")):
                (payload / f"{label}.requirements.txt").write_bytes(raw_inputs[index])
                (payload / f"{label}.download.log").write_text(logs[index], encoding="utf-8", newline="\n")
            provenance = {
                "schema": "tomorrowci.python-dependency-import/v1",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "importer_sha256": digest(Path(__file__).read_bytes()),
                "mode": "offline-wheelhouse" if wheelhouse else "docker-pypi-wheel-download",
                "runtime": runtime, "container_image": image,
                "download_network": "not-used" if wheelhouse else "bridge",
                "index_url": None if wheelhouse else "https://pypi.org/simple",
                "input_sha256": {label: digest(raw) for label, raw in zip(("before", "after"), raw_inputs)},
                "hash_locked": {label: all(pin.hashes for pin in pins.values())
                                for label, pins in zip(("before", "after"), pin_sets)},
                "manifest_sha256": digest(manifest_bytes),
                "changed_count": len(changes), "unchanged_count": len(unchanged),
                "artifacts": [artifacts[key] for key in sorted(artifacts)],
                "scope": {
                    "closure": "full exact pin sets required; each probe validates Requires-Dist offline",
                    "compatibility": "NOT_RUN: import is not a scan, installation or replay",
                    "additions_removals": "unsupported", "sdists": "unsupported; wheels only",
                    "offline_platform_selection": "not asserted" if wheelhouse else "selected by pinned container pip",
                },
            }
            (payload / "provenance.json").write_bytes(canonical_json(provenance))
            staged_manifest = stage / MANIFEST
            staged_manifest.write_bytes(manifest_bytes)
            # Reserve a new directory exclusively; never rename over a user path.
            validate_output(target, output_dir)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.mkdir(exist_ok=False)
            published_directory = True
            for child in payload.iterdir():
                child.rename(destination / child.name)
            # A hard link is an atomic, no-replace commit marker on NTFS/ext4.
            # All referenced artifacts exist before the manifest becomes visible.
            os.link(staged_manifest, manifest_path)
            return {"manifest": str(manifest_path), "provenance": str(destination / "provenance.json"),
                    "changes": len(changes), "unchanged": len(unchanged)}
    except (OSError, zipfile.BadZipFile) as error:
        detail = f"; staged artifacts retained at {destination}" if published_directory else ""
        raise ImportErrorDetail(f"import could not publish without overwriting existing files: {error}{detail}") from error
    finally:
        lock_path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True, help="existing disposable target checkout")
    parser.add_argument("--before", type=Path, required=True, help="complete baseline exact pin snapshot")
    parser.add_argument("--after", type=Path, required=True, help="complete candidate exact pin snapshot")
    parser.add_argument("--runtime", required=True, help="canonical Python major.minor, e.g. 3.11")
    parser.add_argument("--image", required=True, help="locally loaded immutable image@sha256 digest")
    parser.add_argument("--output-dir", default="vendor/python-dependencies", help="new workspace-relative artifact directory")
    parser.add_argument("--wheelhouse", type=Path, help="bounded flat offline wheel directory; skips Docker/downloads")
    parser.add_argument("--require-hashes", action="store_true", help="require SHA256 locks for every before/after pin")
    parser.add_argument("--timeout-seconds", type=int, default=300, help="per-snapshot download wall limit (1–1800)")
    args = parser.parse_args(argv)
    try:
        result = import_dependencies(**vars(args))
    except (ImportErrorDetail, OSError) as error:
        print(f"import: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    print("import: READY; dependency compatibility and minimality require scan/verify/replay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
