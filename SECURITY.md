# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please email security findings to the maintainers privately (open a GitHub Security Advisory when the repo is public). Do not file public issues for exploitable sandbox escapes.

## Scope

In scope: sandbox isolation bugs, secret leakage into containers/logs/reports, path traversal in workspace handling, XSS in HTML reports.

Out of scope: vulnerabilities solely in third-party base images or the container engine itself (report upstream).
