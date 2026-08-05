# Contributing

## Develop

```bash
cargo test --workspace
cargo build -p tomorrowci --release
./target/release/tomorrowci doctor
```

## Rules

- Do not add LLM calls to the verdict path.
- Do not execute fixture/target code on the host in library defaults.
- Mark missing infrastructure as `BLOCKED`, not `PASS`.
- Prefer small vertical slices with real tests over broad mocks.

## PRs

- Include rationale for adapter/security changes.
- Update docs when behavior changes.
- Keep Apache-2.0 headers/license intact.
