# Support policy

## Supported platforms (v0.1)

| Platform | CLI | Container execution |
|----------|-----|---------------------|
| Linux x86_64 | Supported | Docker or Podman |
| macOS (Intel/ARM) | Supported (build from source) | Docker Desktop / Colima |
| Windows x86_64 | Supported (build from source) | Docker Desktop (Linux engine) |

## Supported ecosystems

| Ecosystem | Package manager | Status |
|-----------|-----------------|--------|
| Python | pip (uv documented as allowed) | Implemented |
| Node.js | npm only | Implemented |
| Rust | cargo | Implemented |

Unsupported managers return `UNSUPPORTED` — never silent fallback.

## What we do not support yet

- Remote `scan https://github.com/...` full clone flow
- yarn / pnpm / poetry / pipenv as first-class managers
- Multi-tenant SaaS isolation guarantees
- Guaranteed production container breakout resistance

## Release support window

- **v0.1.x**: best-effort security fixes for 6 months after release
- Breaking changes require a minor/major bump and CHANGELOG entry

## Getting help

- GitHub Issues for bugs and feature requests
- Security issues: see `SECURITY.md`
