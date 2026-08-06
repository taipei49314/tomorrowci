# Threat model (draft)

## Assets

- Integrity of verdicts and evidence bundles
- Host secrets and environment
- Docker/Podman host
- User source repositories (must not be mutated)

## Trust boundaries

| Zone | Trust |
|------|-------|
| TomorrowCI CLI/core | Trusted |
| Container engine | Trusted computing base |
| Target repository code | **Untrusted** |
| Fetched packages | Untrusted |
| Generated HTML from logs | Untrusted content (must escape) |

## Attacker goals

- Escape container to host
- Steal host secrets via env/mounts
- Poison verdicts (false PASS)
- Exfiltrate data via network during tests
- Symlink escape from workspace mounts

## Mitigations (product requirements)

- No host execution of targets by default
- No privileged containers
- No docker.sock mount into target
- No arbitrary host env forwarding
- Disposable worktree/copy
- Resource limits (CPU/mem/PID/time)
- Network off during test phase; fetch-only separated
- Symlink escape checks
- Log redaction + HTML escaping
- Evidence checksums

## Residual risk

Container breakout bugs, malicious images, and compromised package registries remain in scope for residual risk and must be documented honestly. Podman may be unavailable on some hosts → execution `BLOCKED`, not silent host fallback.

## Out of scope (v0.1)

- Formal verification of container runtime
- Multi-tenant SaaS isolation guarantees
