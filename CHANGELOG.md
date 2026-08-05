# Changelog

## 0.1.0 — 2026-08-05

### Added

- Initial public release candidate of TomorrowCI
- Rust CLI: `scan`, `show`, `replay`, `explain`, `report`, `doctor`, `init-action`
- Adapters: Python (pip), Node (npm), Rust (cargo)
- Docker/Podman sandbox with resource limits and network split
- Budget-aware planner, failure reruns, flaky classification, ddmin helpers
- Evidence bundles with checksums and replay manifests
- HTML / JSON / SARIF reports
- Fixtures for runtime break, dependency, flaky, baseline-fail, node, rust
- GitHub Action workflow generator and CI workflows
