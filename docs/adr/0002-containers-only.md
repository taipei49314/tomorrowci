# ADR 0002: Containers-only execution

## Decision

Never execute untrusted target code on the host by default. Require Docker or Podman.

## Consequences

Environments without a container engine receive `BLOCKED` with actionable doctor output. Integration e2e is blocked on such hosts (honest, not faked as PASS).
