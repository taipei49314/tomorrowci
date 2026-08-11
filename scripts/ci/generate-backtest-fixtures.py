#!/usr/bin/env python3
"""Regenerate the tiny, deterministic offline dependency snapshots used by CI."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import pathlib
import tarfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SNAPSHOTS = ROOT / "fixtures" / "backtest-snapshots"
EFFECTIVE_AT = "2026-01-15T12:00:00Z"
CAPTURED_AT = "2026-01-15T13:00:00Z"
HASH_EFFECTIVE_AT = "2026-01-15T12:00:00+00:00"
HASH_CAPTURED_AT = "2026-01-15T13:00:00+00:00"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={encoded.decode('ascii')}"


def add_zip_file(archive: zipfile.ZipFile, path: str, data: bytes) -> None:
    entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.create_system = 3
    entry.external_attr = 0o100644 << 16
    archive.writestr(entry, data)


def python_wheel() -> bytes:
    files = {
        "tomorrowci_snapshot_dep/__init__.py": (
            b'def snapshot_value():\n    return "python-snapshot-dependency-1.0.0"\n'
        ),
        "tomorrowci_snapshot_dep-1.0.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\n"
            b"Name: tomorrowci-snapshot-dep\n"
            b"Version: 1.0.0\n"
            b"Summary: Deterministic TomorrowCI offline snapshot fixture\n"
        ),
        "tomorrowci_snapshot_dep-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: tomorrowci-fixture-generator\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
    }
    record_path = "tomorrowci_snapshot_dep-1.0.0.dist-info/RECORD"
    rows = [
        [path, record_digest(data), str(len(data))]
        for path, data in sorted(files.items())
    ]
    rows.append([record_path, "", ""])
    record = io.StringIO(newline="")
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[record_path] = record.getvalue().encode("utf-8")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for path, data in sorted(files.items()):
            add_zip_file(archive, path, data)
    return output.getvalue()


def npm_package() -> bytes:
    files = {
        "package/index.js": (
            b"'use strict';\n"
            b"exports.snapshotValue = () => 'node-snapshot-dependency-1.0.0';\n"
        ),
        "package/package.json": json.dumps(
            {
                "name": "tomorrowci-snapshot-dep",
                "version": "1.0.0",
                "main": "index.js",
            },
            indent=2,
            separators=(",", ": "),
        ).encode("utf-8")
        + b"\n",
    }
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, data in sorted(files.items()):
                entry = tarfile.TarInfo(path)
                entry.size = len(data)
                entry.mode = 0o644
                entry.mtime = 0
                entry.uid = 0
                entry.gid = 0
                entry.uname = ""
                entry.gname = ""
                archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def write_bytes(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: pathlib.Path, data: str) -> None:
    write_bytes(path, data.encode("utf-8"))


def inventory(payload: pathlib.Path) -> list[dict[str, object]]:
    files = []
    for path in sorted(item for item in payload.rglob("*") if item.is_file()):
        relative = path.relative_to(payload).as_posix()
        data = path.read_bytes()
        files.append({"path": relative, "sha256": digest(data), "size": len(data)})
    return files


def framed(hasher: "hashlib._Hash", value: str) -> None:
    data = value.encode("utf-8")
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def snapshot_id(
    ecosystem: str,
    source_url: str,
    immutable_revision: str,
    resolver_mode: str,
    files: list[dict[str, object]],
) -> str:
    hasher = hashlib.sha256()
    for value in [
        "tomorrowci-registry-snapshot-v1",
        "1",
        ecosystem,
        HASH_EFFECTIVE_AT,
        HASH_CAPTURED_AT,
        source_url,
        immutable_revision,
        resolver_mode,
    ]:
        framed(hasher, value)
    for entry in files:
        framed(hasher, str(entry["path"]))
        framed(hasher, str(entry["sha256"]))
        framed(hasher, str(entry["size"]))
    return f"sha256:{hasher.hexdigest()}"


def write_manifest(ecosystem: str, source_url: str, resolver_mode: str) -> None:
    snapshot = SNAPSHOTS / ecosystem / "2026-01-15"
    files = inventory(snapshot / "payload")
    capture_material = "".join(
        f'{entry["path"]}\0{entry["sha256"]}\0{entry["size"]}\n' for entry in files
    ).encode("utf-8")
    immutable_revision = f"sha256:{digest(capture_material)}"
    manifest = {
        "schema_version": 1,
        "snapshot_id": snapshot_id(
            ecosystem, source_url, immutable_revision, resolver_mode, files
        ),
        "ecosystem": ecosystem,
        "effective_at": EFFECTIVE_AT,
        "captured_at": CAPTURED_AT,
        "source": {
            "url": source_url,
            "immutable_revision": immutable_revision,
        },
        "resolver_mode": resolver_mode,
        "files": files,
    }
    write_text(
        snapshot / "snapshot-manifest.json",
        json.dumps(manifest, indent=2, separators=(",", ": ")) + "\n",
    )


def main() -> None:
    write_bytes(
        SNAPSHOTS
        / "python/2026-01-15/payload/tomorrowci_snapshot_dep-1.0.0-py3-none-any.whl",
        python_wheel(),
    )
    write_bytes(
        SNAPSHOTS
        / "node/2026-01-15/payload/tomorrowci-snapshot-dep-1.0.0.tgz",
        npm_package(),
    )

    rust = SNAPSHOTS / "rust/2026-01-15/payload/tomorrowci-snapshot-dep-1.0.0"
    cargo_toml = (
        "[package]\n"
        'name = "tomorrowci-snapshot-dep"\n'
        'version = "1.0.0"\n'
        'edition = "2021"\n'
        'description = "Deterministic TomorrowCI offline snapshot fixture"\n'
        'license = "MIT"\n'
        "\n[lib]\n"
        'path = "src/lib.rs"\n'
    )
    rust_lib = (
        'pub fn snapshot_value() -> &\'static str {\n'
        '    "rust-snapshot-dependency-1.0.0"\n'
        "}\n"
    )
    write_text(rust / "Cargo.toml", cargo_toml)
    write_text(rust / "src/lib.rs", rust_lib)
    checksum = {
        "files": {
            "Cargo.toml": digest(cargo_toml.encode("utf-8")),
            "src/lib.rs": digest(rust_lib.encode("utf-8")),
        },
        "package": "a" * 64,
    }
    write_text(
        rust / ".cargo-checksum.json",
        json.dumps(checksum, sort_keys=True, separators=(",", ":")) + "\n",
    )

    write_manifest("python", "https://pypi.org/simple/", "python_wheelhouse")
    write_manifest("node", "https://registry.npmjs.org/", "npm_offline_cache")
    write_manifest(
        "rust", "https://github.com/rust-lang/crates.io-index", "cargo_vendor"
    )


if __name__ == "__main__":
    main()
