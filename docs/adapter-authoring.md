# Adapter authoring

Implement `tomorrowci_adapters::EcosystemAdapter`:

```rust
fn contract(&self) -> AdapterContract;
fn detect(&self, repo: &Path) -> Result<DetectionResult>;
fn baseline(&self, repo: &Path, config: &Config) -> Result<Baseline>;
fn candidates(&self, baseline: &Baseline, config: &Config) -> Result<Vec<Candidate>>;
fn materialize(&self, scenario: &Scenario, workspace: &Path) -> Result<EnvironmentSpec>;
fn commands(&self, scenario: &Scenario, config: &Config) -> Result<Vec<CommandSpec>>;
fn commands_in_workspace(
    &self,
    scenario: &Scenario,
    config: &Config,
    workspace: &Path,
) -> Result<Vec<CommandSpec>>;
fn normalize_failure(&self, result: &RawExecutionResult) -> FailureSignature;
```

`commands_in_workspace` has a compatibility default that delegates to
`commands`; adapters that materialize historical/offline inputs override it so
command generation can bind only paths inside the disposable workspace.

Return `AdapterContract::v1()` and run the shared `assert_adapter_conforms`
suite before registration. See [`adapter-sdk.md`](adapter-sdk.md) and the
minimal external-style crate in `crates/adapter-example`.

## Rules

1. **Do not** spawn unrestricted host shells.
2. Emit **argument arrays**, not `sh -c` blobs, whenever possible.
3. Mark unsupported package managers as `supported: false` with a clear reason.
4. Only propose candidates that map to **real published** images/tags.
5. Separate `CommandPhase::Fetch` (network) from `Test` (no network).
6. Normalize failures into typed `FailureSignature` fingerprints.

## v0.2 built-in managers

| Ecosystem | Supported | Unsupported examples |
|---|---|---|
| Python | pip | Poetry-only, Pipenv-only |
| Node | npm + package-lock.json | Yarn-only, pnpm-only |
| Rust | cargo | — |
