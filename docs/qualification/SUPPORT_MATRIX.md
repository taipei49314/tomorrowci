# Candidate support matrix

Candidate version: `0.2.0` (untagged until promotion gates pass).

This matrix distinguishes implemented support from release qualification. A
row marked `BLOCKED` is not a product PASS and cannot authorize a stable tag.

| Surface | Implemented contract | Candidate qualification |
|---|---|---|
| Linux x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | `PASS_PUBLIC_CI` on `945f458`; frozen candidate archive/read-back pending |
| Windows x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | `PASS_PUBLIC_CI` on `945f458`; frozen candidate archive/read-back pending |
| macOS x86_64 CLI | Build, package, `--version`, doctor, report/verify smoke | `PASS_PUBLIC_CI` on macOS Intel at `945f458`; frozen archive architecture/read-back pending |
| Rust build toolchain | MSRV 1.85 against the locked workspace; release builds use pinned Rust 1.97.1 | `PASS_PUBLIC_CI`: dedicated MSRV, locked workspace, audit, and required Rust CI passed at `945f458` |
| Docker | Six built-in fixtures, sealed v2 evidence, exact replay qualification | `PASS_PUBLIC_CI`: downloaded artifact 9090824623 reverified at `945f458` |
| Podman | Six built-in fixtures, sealed v2 evidence, exact replay qualification | `PASS_PUBLIC_CI`: hosted Podman 4.9.3 artifact 9090823667 reverified at `945f458` |
| Canonical GitHub remote source | Bounded HTTPS clone, credential isolation, exact captured commit, and fail-closed gitlink/LFS/link checks | `PASS_PUBLIC_CI` executable/negative contract at `945f458`; candidate archive read-back pending |
| Python / pip | `pyproject.toml` and `requirements.txt` projects | Built-in fixture qualified; external target and independent audit pending |
| Node.js / npm | `package.json` plus npm lockfile projects | Built-in fixture qualified; external target and independent audit pending |
| Rust / cargo | `Cargo.toml` and Cargo lockfile projects | Built-in fixture qualified; external target and independent audit pending |
| Historical backtest | Exact Git-object materialization plus content-addressed, offline registry snapshots | `PASS_PUBLIC_CI`: downloaded Python/Node/Rust offline proofs reverified at `945f458` |
| Ecosystem weather map | Predeclared denominator aggregated only through verified v2 run generations | `PASS_PUBLIC_CI`: typed negatives and real-binary contract passed at `945f458` |
| Patch Lab | Strict unified diff, disposable scan/replay, changed-byte witnesses, and detached proof verification | `PASS_PUBLIC_CI`: downloaded `QUALIFIED` proof reverified against both sealed runs at `945f458` |
| Adapter SDK | Versioned contract negotiation, safety validator, conformance kit, and external-style example | `PASS_PUBLIC_CI`: built-ins plus external-style example passed conformance at `945f458` |
| Poetry, Pipenv, Yarn, pnpm-only projects | Explicitly unsupported; no silent fallback | Expected `UNSUPPORTED`, never PASS |
| Explicit host mounts during exact replay | Rejected fail-closed | `BLOCKED` until source-bound mount identity exists |
| Stable `v0.2.0` promotion | Byte-identical promotion of audited dry-run assets | `BLOCKED_EXTERNAL` until the external evidence index contains a qualifying independent result |

The machine-readable gate inventory remains
[`BACKLOG.json`](BACKLOG.json); independent evidence is recorded only in
[`EXTERNAL_EVIDENCE_INDEX.json`](EXTERNAL_EVIDENCE_INDEX.json).
