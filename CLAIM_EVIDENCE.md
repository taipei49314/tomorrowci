# Claim-to-evidence ledger (local builder host)

Host: Windows without Docker/Podman/WSL. Container e2e is BLOCKED by design (not faked as PASS).

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace builds | PASS | `cargo build -p tomorrowci --release` | exit 0 | `target/release/tomorrowci.exe` |
| Unit/integration tests | PASS | `cargo test --workspace` | 39 tests ok | - |
| Doctor reports sandbox | PASS | `tomorrowci doctor` | sandbox blocked | - |
| Scan without engine is BLOCKED | PASS | `tomorrowci scan fixtures/python-runtime-break` | exit 4 BLOCKED | `.tomorrowci/runs/41b270775798/` |
| Python adapter unit tests | PASS | cargo test -p tomorrowci-adapter-python | 3 ok | - |
| Node adapter unit tests | PASS | cargo test -p tomorrowci-adapter-node | 2 ok | - |
| Rust adapter unit tests | PASS | cargo test -p tomorrowci-adapter-rust | 1 ok | - |
| Replay from recorded manifest | NOT_RUN (engine) | requires docker for execution | BLOCKED without engine | evidence has replay-manifest only after successful scenario |
| HTML report XSS test | PASS | cargo test -p tomorrowci-report | ok | - |
| HTML demo report | PASS (generator) | report example gen_demo | ok | `examples/reports/python-runtime-break.html` |
| Real fixture container horizon | BLOCKED | no Docker/Podman on builder | - | CI job `container-integration` on ubuntu |
| Frontend tests | PASS | `npm test` in apps/web | 3 ok after fix | - |
| Frontend build | PASS | `npm run build` | dist produced | `apps/web/dist` |
| GitHub Action dogfood | NOT_RUN | needs GH Actions | workflow + action present | `.github/workflows/ci.yml`, `action/` |
| Release dry run | PASS | package zip + sha256 + sbom | ok | `release-dry-run/` |

