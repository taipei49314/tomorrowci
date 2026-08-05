# Threat model

## Assets

- Integrity of **verdicts and evidence** (must not lie)
- Confidentiality of **host secrets** (tokens, keys, env)
- Integrity of the **user’s repository** (must not be mutated)
- Availability of the **host** (CPU/memory/disk from runaway builds)

## Trust boundaries

| Zone | Trust |
|---|---|
| TomorrowCI binary + host config | Trusted |
| Container engine (Docker/Podman) | Trusted TCB |
| Target repository code & dependencies | **Untrusted** |
| Container images from registries | Partially trusted (pin digests when possible) |
| Generated HTML reports | Untrusted content, must be escaped |

## Attacker goals

1. Escape container and access host files/secrets.
2. Exfiltrate CI secrets via network during tests.
3. Poison evidence to hide a future break or invent one.
4. Abuse TomorrowCI as a free compute/network botnet.
5. XSS via malicious test logs in HTML reports.

## Mitigations

| Control | Implementation |
|---|---|
| No host execution by default | Sandbox-only path; doctor/scan block without engine |
| No privileged containers | Never pass `--privileged` |
| No docker.sock mount | Explicit reject if path contains `docker.sock` |
| Env isolation | Do not forward host env; forbid secret-like keys |
| Disposable workspace | Copy/worktree; skip following symlinks on copy |
| Resource limits | memory, cpus, pids, wall clock |
| Network split | Fetch may use network; tests use `network=none` |
| Log redaction | API keys, `ghp_`, AWS keys, PEM headers |
| HTML escaping | All untrusted strings escaped in report |
| Log caps | Truncate oversized stdout/stderr |

## Known limitations (residual risk)

- Container breakout vulnerabilities in the engine/kernel.
- Malicious or compromised base images.
- `fetch-only` still allows network during dependency install (supply chain).
- Non-root user not always possible when package installs need root inside the image.
- Root filesystem not always read-only when package managers need writes.
- Symlink escape checks are best-effort on Windows.
- No seccomp/AppArmor profile customization in v0.1 beyond engine defaults + `no-new-privileges`.

## Out of scope (v0.1)

- Multi-tenant SaaS isolation
- Formal verification of the planner
- Guarantees against intentional flaky sabotage beyond classification
- Signing of evidence bundles (path documented for future provenance)

## Reporting

See [SECURITY.md](../SECURITY.md).
