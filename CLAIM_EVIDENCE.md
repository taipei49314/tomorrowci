# Claim-to-evidence ledger

Qualification snapshot: 2026-08-09 (Asia/Taipei), baseline SHA `1f42003a561630164699f94f274727be23f2c1a8`.

The local audit host is Windows. Docker CLI 29.6.2 was present but its daemon was unavailable during the initial baseline; Docker Desktop 29.6.2 subsequently became available for the exact branch-candidate run recorded below. The Podman command remains missing. Public CI evidence is identified separately and applies only to its exact SHA. Local project-owned evidence does not count as independent external adoption. Full commands, fixture outcomes, release hashes, and truth boundaries are in [`docs/qualification/BASELINE.md`](docs/qualification/BASELINE.md); machine-readable open gates are in [`docs/qualification/BACKLOG.json`](docs/qualification/BACKLOG.json).

| Claim | Status | Command / scope | Result | Evidence |
|---|---|---|---|---|
| Rust formatting | PASS | `cargo fmt --all -- --check` | exit 0 | Local baseline |
| Rust lint | PASS | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 | Local baseline |
| Rust unit/integration tests | PASS | `cargo test --workspace` | 52 tests: `2+3+1+37+1+4+2+2` | Local baseline |
| Rust release build | PASS | `cargo build -p tomorrowci --release` | exit 0 | `target/release/tomorrowci.exe` |
| CLI version | PASS | `target/release/tomorrowci.exe --version` | `tomorrowci 0.1.0` | Local baseline |
| Doctor finds a usable local sandbox | BLOCKED_LOCAL | `target/release/tomorrowci.exe doctor` | exit 4; Docker daemon unavailable; Podman missing; npm false-negative also observed | Local baseline |
| Six built-in Docker fixture expectations | PASS_PUBLIC_CI | `measure all` / scan on exact default SHA | all six expectation contracts passed; combined claim count `56 PASS`, `0` other | [container job](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889106516), [step 5](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889106516#step:5:1), [baseline detail](docs/qualification/BASELINE.md#six-built-in-fixture-outcomes) |
| Six local Docker fixtures plus bundle verification | PASS_LOCAL_CANDIDATE | Docker Desktop 29.6.2 on Windows; exact commit `aeb51a81d2e1288b9d5f16b5ea4e8ed39c9ff544`; `2026-08-09T12:00:00Z`–`2026-08-09T12:12:57Z` | six fixtures; `trustworthy=true`; `56 PASS`, `0` other; all six run bundles verified PASS | Local project-owned `%TEMP%` evidence: `5234ee587e61`/64 files, `5f6f01c0e9e4`/21, `83b8bfa7a323`/52, `bc8cb37e8bb4`/42, `c8d5dd2d8165`/73, `f31d689fe013`/21; [detail](docs/qualification/BASELINE.md#subsequent-local-docker-branch-candidate-evidence) |
| Live Podman fixture suite | NOT_RUN | Local Podman command absent; inspected public job used Docker only | no Podman evidence | [`CI-003`](docs/qualification/BACKLOG.json) |
| End-to-end replay | NOT_RUN | required `scan -> verify -> replay x2 -> verify` | public measure run scanned only; replay text was a suggested command | [`QUAL-003`](docs/qualification/BACKLOG.json) |
| First-class evidence verification | OPEN | baseline CLI surface | no `verify` subcommand at this SHA | [`QUAL-001`](docs/qualification/BACKLOG.json) |
| HTML report tests, including escaping coverage | PASS | covered by `cargo test --workspace` | report crate tests passed | Local baseline |
| HTML demo report generation | NOT_RUN_THIS_BASELINE | example generator | historical generated file exists, but generator was not rerun in this audit | `examples/reports/python-runtime-break.html` |
| Frontend dependency install | PASS_WITH_FINDINGS | `npm ci` in `apps/web` | completed; audit reports 3 moderate, 1 high, 1 critical vulnerability | [`WEB-001`](docs/qualification/BACKLOG.json) |
| Frontend tests | PASS | `npm test -- --run` in `apps/web` | Vitest `3/3` | Local baseline |
| Frontend build | PASS | `npm run build` in `apps/web` | production build completed | Local baseline |
| GitHub Action dogfood | PASS_PUBLIC_CI | exact SHA `1f42003a561630164699f94f274727be23f2c1a8` | job completed successfully | [run 31185394369](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369), [job 92889107297](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889107297) |
| Existing release archive checksums | FAIL_INCOMPLETE | read-back of `v0.1.0-grok-session` | all 3 listed archive hashes match, but `sbom.cdx.json` is omitted | [release](https://github.com/taipei49314/tomorrowci/releases/tag/v0.1.0-grok-session), [`RELEASE-003`](docs/qualification/BACKLOG.json) |
| Existing release SBOM | FAIL | read-back of `sbom.cdx.json` | CycloneDX 1.5 parses, but `components=[]` while `Cargo.lock` has 105 packages | [`RELEASE-002`](docs/qualification/BACKLOG.json) |
| Existing macOS release target identity | FAIL | archive/header inspection | asset is labeled `x86_64`; contained Mach-O is `arm64` | [`RELEASE-001`](docs/qualification/BACKLOG.json) |
| Independent external adopter/auditor replay | BLOCKED_EXTERNAL | requires a genuinely independent trust root | no qualifying evidence inspected; project-owned CI cannot satisfy it | [`EXTERNAL-002`](docs/qualification/BACKLOG.json) |
| New stable tag/release | BLOCKED_BY_GATES | exact-SHA release contract | do not publish until technical, release, Podman, and external gates close | [`RELEASE-005`](docs/qualification/BACKLOG.json) |
