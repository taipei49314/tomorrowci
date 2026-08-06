# ADR 0002: No host execution of target code by default

## Status

Accepted

## Context

Scanned repositories are untrusted. Host execution would violate the product’s
security thesis and the mission disqualification conditions.

## Decision

- Default path requires Docker or Podman.
- `refuse_host_execution()` and `SecurityPolicy` reject privileged mode and docker.sock mounts.
- Scripted executors exist **only** for unit/integration tests of planner logic.
- When the daemon is unavailable, report `BLOCKED` — never silent host fallback.

## Consequences

+ Honest security story  
+ CI may report BLOCKED on runners without Docker images  
− Local demos require container runtime for live e2e  
