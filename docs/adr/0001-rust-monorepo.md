# ADR 0001: Rust monorepo with typed crates

## Status

Accepted

## Context

TomorrowCI needs a high-performance CLI, container orchestration, and
deterministic verdicts without coupling adapters to UI or CI wrappers.

## Decision

Use a Cargo workspace monorepo:

- `core` — domain, config, planner, verdict
- `sandbox` / `runner` — isolation and execution
- `adapter-*` — ecosystems
- `evidence` / `report` / `metrics` — outputs and measurement
- `apps/cli` — user interface

## Consequences

+ Clear dependency direction and testability  
+ Single version for v0.1  
− Larger clone for contributors who only want one adapter  
