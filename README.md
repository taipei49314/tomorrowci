# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI finds the earliest **concrete** future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits **replayable evidence**.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

![Architecture](docs/architecture/diagram.md)

## What it is / is not

| TomorrowCI | Not TomorrowCI |
|---|---|
| Tests against real runtime/dependency candidates | A dependency update PR bot |
| OBSERVED / SIMULATED / SCHEDULED_RISK / INCONCLUSIVE grades | Invented future APIs |
| Sandboxed execution (Docker/Podman) | Default host execution of untrusted code |
| Typed verdicts (`BLOCKED` ≠ `PASS`) | Collapsing everything into FAIL/PASS |
| Local-first, no telemetry, no cloud account | A SaaS-only scanner |

## Status (public v0.1 candidate)

| Milestone | Status |
|-----------|--------|
| M0 Repository contract | Done |
| M1 Python vertical slice | Done |
| M2 Planner / deps / ddmin / flaky | Done |
| M3 Node + Rust adapters | Done |
| M4 Action + accessible report + compare | Done |
| M5 Release candidate docs + dry-run | Done |

See [docs/CLAIM_TO_EVIDENCE.md](docs/CLAIM_TO_EVIDENCE.md) for the full claim matrix.

## Quick start

**Prerequisites:** Rust toolchain; Docker or Podman for live scans.

```bash
git clone <this-repo>
cd tomorrowci
cargo build -p tomorrowci-cli --release

./target/release/tomorrowci doctor
./target/release/tomorrowci trust
./target/release/tomorrowci scan fixtures/python-runtime-break
```

Without a container daemon, `scan` correctly returns **BLOCKED** (not a silent host run).

Generate the committed demo HTML report (scripted evidence, no Docker):

```bash
cargo run -p tomorrowci-gen-demo
# open examples/reports/python-runtime-break/report.html
```

## CLI

```bash
tomorrowci doctor
tomorrowci trust
tomorrowci scan <path> [--config .tomorrowci.yml]
tomorrowci show <run-id>
tomorrowci replay <run-id> --scenario <id>
tomorrowci explain <run-id>
tomorrowci report <run-id> --format html|json|sarif|summary
tomorrowci metrics <run-id>
tomorrowci compare --base <id> --head <id> [--gate]
tomorrowci init-action
```

## Configuration

Schema: `packages/schema/tomorrowci-config.schema.json`  
Example: `fixtures/python-runtime-break/.tomorrowci.yml`

## Fixtures

| Fixture | Intent |
|---------|--------|
| `fixtures/python-runtime-break` | Stdlib break on newer Python |
| `fixtures/python-dependency-break` | Dependency-axis failure |
| `fixtures/node-dependency-break` | Node runtime API break (`toSorted`) |
| `fixtures/rust-msrv-break` | Older rustc cannot compile LazyCell |

## GitHub Action

Composite action: [`action/action.yml`](action/action.yml)  
Template: `tomorrowci init-action`

Permissions default to `contents: read`. Advisory mode does not fail the job on horizon findings; policy gate is explicit.

## Release

```bash
# Windows
./scripts/release-dry-run.ps1

# Unix
./scripts/release-dry-run.sh
```

See [docs/RELEASE.md](docs/RELEASE.md). Tag `v*` triggers `.github/workflows/release.yml`.

## Security

- Target code is **never** executed on the host by default
- No privileged containers; no docker.sock into the target
- Residual container escape risk is documented in [docs/threat-model](docs/threat-model/README.md)
- Report untrusted HTML is escaped; see `SECURITY.md`

## Documentation

- [Architecture](docs/architecture/README.md) · [Diagram](docs/architecture/diagram.md)
- [Threat model](docs/threat-model/README.md)
- [Adapter authoring](docs/adapter-authoring/README.md)
- [Report format](docs/report-format/README.md)
- [ADRs](docs/adr/)
- [Terminal demo](docs/demo/terminal-session.md)
- [Support policy](SUPPORT.md)

## License

Apache-2.0 — see [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
