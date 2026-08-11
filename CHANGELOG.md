# Changelog

## 0.2.0

### Added

- Evidence inventory v2 with source, configuration, engine, image, command,
  environment, original-attempt, replay-attempt, and qualification identities
- Two digest-pinned scan-time replay receipts for observed future failures,
  with verifier-recomputed equivalence before horizon authorization
- First-class fail-closed `verify` command and verify-before-consume gates
- Exact-set recursive bundle sealing, typed cross-file validation, bounded
  reads, deterministic sealed reports, and Windows path protections
- Content-addressed offline historical backtests with detached
  `backtest-verify` proof readback
- Predeclared-denominator ecosystem weather maps built only from retained
  verified run generations
- Patch Lab proposal/proof commands and a real-binary contract suite covering
  the documented CLI surface and exit codes
- Versioned adapter API 1.0 capability negotiation, safety validation,
  conformance fixtures, three built-in conformance runs, and an external-style
  adapter example
- Bounded canonical GitHub HTTPS acquisition with exact source identity and
  fail-closed submodule, LFS, symlink/reparse, credential, and redirect rules
- Docker and explicit Podman fixture gates, three-OS CLI smoke, evidence
  mutation tests, and a source-separated Action consumer job

### Changed

- The declared minimum supported Rust version is now 1.85, matching the
  locked dependency graph and enforced by a dedicated CI job
- Public replay now requires the recorded image digest and unchanged source,
  runs in a fresh workspace, accepts an exact source-bound `--workspace` for
  downloaded v2 evidence, and returns exit 3 for reproduced target failures
- Original reruns share one isolated measurement workspace so state-dependent
  flakiness remains observable; qualification replays remain independent
- Release engineering now targets reproducible `0.2.0` dry-run candidates;
  deterministic three-platform archives, a complete workspace SBOM, GitHub
  provenance, project-operated external runs, and byte-identical stable
  promotion remain gated on independent external qualification
- The composite Action now builds from its own checkout, passes inputs through
  environment variables, selects exactly the newly created run, and fails
  closed on verification or internal errors even in advisory mode

## 0.1.0 — 2026-08-05

### Added

- Initial public release candidate of TomorrowCI
- Rust CLI: `scan`, `show`, `replay`, `explain`, `report`, `doctor`, `init-action`
- `measure` harness (bench / suite / all) with PASS/FAIL/BLOCKED claim ledger
- `compare` base vs head horizon regression detection (`--fail-on-regression`)
- `policy` fail-if gate (baseline / future fail / regression / blocked ratio)
- `backtest` commit-sampling skeleton (honest M2 limits documented)
- Bounded parallel scenario execution via `execution.max_parallel`
- Adapters: Python (pip), Node (npm), Rust (cargo)
- Docker/Podman sandbox with resource limits and network split
- Budget-aware planner, failure reruns, flaky classification, ddmin helpers
- Evidence bundles with checksums and replay manifests
- HTML / JSON / SARIF reports
- Fixtures for runtime break, dependency, flaky, baseline-fail, node, rust
- GitHub Action workflow generator and CI workflows
