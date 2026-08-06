# Changelog

All notable changes to TomorrowCI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-06

### Added

- Domain model, config schema, verdict and breakage-horizon authorization
- Budget-aware planner, failure reruns, flaky classification, ddmin axis reduction
- Ecosystem adapters: Python (pip), Node (npm), Rust (cargo)
- Docker/Podman sandbox executor with safe defaults (no host target execution)
- Evidence bundles with checksums, replay scripts, HTML/JSON/SARIF reports
- Scan metrics instruments and claim-to-evidence ledger
- Trust-behavior audit (`tomorrowci trust`)
- GitHub composite Action, job summary, base/head horizon compare + policy gate
- Fixtures: python-runtime-break, python-dependency-break, node-dependency-break, rust-msrv-break
- Release dry-run tooling and documentation suite for public v0.1

### Security

- Privileged containers and docker.sock mounts rejected by policy
- Fetch/test network phases separated; secrets scrubbed from container env
- HTML report escapes untrusted content; ANSI stripped from logs

### Known limitations

- Live container e2e requires a running Docker/Podman daemon
- yarn/pnpm, poetry, and remote GitHub clone scan are unsupported or incomplete
- SBOM/signing use cargo-based dry-run scripts; full SLSA provenance is documented as future work
