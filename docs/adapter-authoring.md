# Adapter authoring

Implement `tomorrowci_adapters::EcosystemAdapter`:

```rust
fn detect(&self, repo: &Path) -> Result<DetectionResult>;
fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline>;
fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>>;
fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec>;
fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>>;
fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature;
```

## Rules

1. **Do not** spawn unrestricted host shells.
2. Emit **argument arrays**, not `sh -c` blobs, whenever possible.
3. Mark unsupported package managers as `supported: false` with a clear reason.
4. Only propose candidates that map to **real published** images/tags.
5. Separate `CommandPhase::Fetch` (network) from `Test` (no network).
6. Normalize failures into typed `FailureSignature` fingerprints.

## v0.1 managers

| Ecosystem | Supported | Unsupported examples |
|---|---|---|
| Python | pip | Poetry-only, Pipenv-only |
| Node | npm + package-lock.json | Yarn-only, pnpm-only |
| Rust | cargo | — |
