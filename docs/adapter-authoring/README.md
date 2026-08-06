# Adapter authoring guide

## Contract

Implement `tomorrowci_adapters::EcosystemAdapter`:

| Method | Responsibility |
|--------|----------------|
| `detect` | Manifests, package manager, confidence; never guess unsupported managers |
| `baseline` | Concrete runtime + dependency mode |
| `candidates` | Ordered concrete versions only (no invented future APIs) |
| `materialize` | EnvironmentSpec (image, limits, network defaults) |
| `commands` | Argv arrays for test phase (no unrestricted host shell) |
| `normalize_failure` | Typed FailureSignature from RawExecutionResult |

## Rules

1. Unsupported package managers → `UNSUPPORTED` error or detection.supported=false.
2. Do not mutate the original repository; runner copies to disposable workspace.
3. Prefer published container tags; digests resolved at execution time.
4. Fetch (network) vs test (no network) are orchestrated by the runner.
5. Unit-test detection and candidate ordering without Docker.

## Registration

Wire detection into `scan_local` in `crates/runner` and document in README ecosystem table.
