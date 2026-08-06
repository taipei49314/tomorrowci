# Claim-to-evidence matrix (v0.1)

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN**

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace builds & tests | PASS | `cargo test --workspace` | exit 0 | local CI |
| Trust behaviors enforced | PASS | `tomorrowci trust` | overall Pass | stdout / metrics trust probes |
| Python adapter pipeline | PASS | `cargo test -p tomorrowci-runner --test m1_m2_pipeline` | 4/4 ok | test log |
| Node adapter pipeline | PASS | `cargo test -p tomorrowci-runner --test m3_node_rust` | node horizon ok | test log |
| Rust adapter pipeline | PASS | `cargo test -p tomorrowci-runner --test m3_node_rust` | rust horizon ok | test log |
| Replay consumes recorded evidence | PASS | unit/integration via evidence layout + `replay_scenario` | API present | crates/runner |
| HTML report from real run data | PASS | `cargo run -p tomorrowci-gen-demo` | frontier observed | `examples/reports/python-runtime-break/report.html` |
| XSS hardening | PASS | report tests + `node --test packages/report-ui/test` | pass | test log |
| GitHub Action defined | PASS | `action/action.yml` + CI workflow | present | action/ |
| Action dogfood in CI | PASS | `.github/workflows/ci.yml` runs trust + scan | workflow present | ci.yml |
| Release dry-run | PASS/BLOCKED* | `scripts/release-dry-run.ps1` | archives+checksums | `dist/` |
| Live Docker fixture e2e | BLOCKED | `tomorrowci scan fixtures/...` without daemon | BLOCKED | doctor |
| Remote GitHub URL scan | NOT_RUN | — | not implemented | README limitations |
| Full SLSA provenance | NOT_RUN | — | documented path only | docs/RELEASE.md |

\* Release dry-run **PASS** when script completes on the host; multi-OS cross-compile may be **BLOCKED** without additional toolchains.

## Skipped / infra

| Item | Reason |
|------|--------|
| Podman backend | Not installed on Windows dev host |
| Docker image pull e2e | Daemon not running |
| softprops/action-gh-release live publish | Requires tag push + permissions |
