# ADR 0001: Package managers for v0.1

## Decision

- Python → **pip**
- Node.js → **npm**
- Rust → **cargo**

## Rationale

Widest official container image support and simplest lock/install semantics for sandboxed CI.

## Consequences

Poetry, Pipenv, Yarn, and pnpm return `UNSUPPORTED` unless compatible manifests exist.
