# Security

## Reporting

Please open a private security advisory or email maintainers for issues that affect sandbox isolation or secret handling.

## Guarantees (v0.1 intent)

- Target code is not executed on the host by default.
- Privileged containers and docker.sock mounts are rejected by policy.
- Residual container escape risk is documented in `docs/threat-model`.
