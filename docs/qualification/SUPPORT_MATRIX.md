# Candidate support matrix

Candidate version: `0.2.0` (untagged until promotion gates pass).

This matrix distinguishes implemented support from release qualification. A
row marked `BLOCKED` is not a product PASS and cannot authorize a stable tag.

| Surface | Implemented contract | Candidate qualification |
|---|---|---|
| Linux x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | Required in release dry-run |
| Windows x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | Required in release dry-run |
| macOS x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | Required in release dry-run; archive label must match Mach-O architecture |
| Rust build toolchain | MSRV 1.85 against the locked workspace; release builds use pinned Rust 1.97.1 | Dedicated MSRV and release-toolchain CI required |
| Docker | Six built-in fixtures, sealed v2 evidence, exact replay qualification | Public project CI required |
| Podman | Container-engine backend is implemented | `BLOCKED`: no retained public v2 fixture acceptance yet |
| Canonical GitHub remote source | Bounded HTTPS clone, credential isolation, exact captured commit, and fail-closed gitlink/LFS/link checks | Public candidate CI evidence pending |
| Python / pip | `pyproject.toml` and `requirements.txt` projects | Built-in fixture qualified; external target and independent audit pending |
| Node.js / npm | `package.json` plus npm lockfile projects | Built-in fixture qualified; external target and independent audit pending |
| Rust / cargo | `Cargo.toml` and Cargo lockfile projects | Built-in fixture qualified; external target and independent audit pending |
| Historical backtest | Exact Git-object materialization plus content-addressed, offline registry snapshots | Three-ecosystem live candidate gate required |
| Ecosystem weather map | Predeclared denominator aggregated only through verified v2 run generations | Real-binary candidate contract required |
| Patch Lab | Strict unified diff, disposable scan/replay, changed-byte witnesses, and detached proof verification | Real-binary candidate contract required |
| Adapter SDK | Versioned contract negotiation, safety validator, conformance kit, and external-style example | Workspace conformance CI required |
| Poetry, Pipenv, Yarn, pnpm-only projects | Explicitly unsupported; no silent fallback | Expected `UNSUPPORTED`, never PASS |
| Explicit host mounts during exact replay | Rejected fail-closed | `BLOCKED` until source-bound mount identity exists |
| Stable `v0.2.0` promotion | Byte-identical promotion of audited dry-run assets | `BLOCKED_EXTERNAL` until the external evidence index contains a qualifying independent result |

The machine-readable gate inventory remains
[`BACKLOG.json`](BACKLOG.json); independent evidence is recorded only in
[`EXTERNAL_EVIDENCE_INDEX.json`](EXTERNAL_EVIDENCE_INDEX.json).
