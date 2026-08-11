# External qualification protocol

This protocol is frozen before target execution. Results are retained even
when they are unfavorable; repositories are not replaced after observing an
outcome without recording the original result and a disqualifying reason.

## Candidate identity

The candidate is the untagged `0.2.0` release-dry-run artifact built from the
final merged default-branch SHA. Its source SHA, workflow run, artifact digest,
candidate-manifest digest, and per-file SHA-256 values must be filled into
`EXTERNAL_EVIDENCE_INDEX.json` before any qualifying run begins.

## Pre-registration

The following corpus was frozen on 2026-08-11 before candidate execution. None
of these repositories is owned by `taipei49314`, and none is a TomorrowCI
fixture. A result is retained even if the selected project fails, is
unsupported, or exposes a TomorrowCI defect.

| Ecosystem | Public target and immutable source | Selection rationale | Config / budget |
|---|---|---|---|
| Python / pip | `jmespath/jmespath.py` at `2812594e69d43098ef60f81f4efc404c071b0418` | Established, compact Python library selected because the exact commit has a root `requirements.txt` whose six non-comment entries are all exact `==` pins, including `pytest==8.4.1`; 62 tracked regular files / 274,352 bytes keep the public run bounded | `project.test_command: python -m pytest -q`; requirements-backed locked baseline; stable runtime candidates; latest dependency candidate; max 6 scenarios; 900 seconds each |
| Node.js / npm | `tj/commander.js` at `ba6d13ddb4243e5913367734f8c159089ffe7834` | Established npm library with `package.json`, `package-lock.json`, and tests; bounded enough for a public container run | `project.test_command: npm test`; locked baseline; stable runtime candidates; latest dependency candidate; max 6 scenarios; 900 seconds each |
| Rust / cargo | `sharkdp/fd` v10.3.0 at `d38148f0aabdd073b4080cde770f679f3197b920` | Established, compact Rust CLI selected because the exact commit tracks its root `Cargo.lock`, declares Rust 1.77.2 (within the configured Rust 1.85 baseline), and has 55 tracked regular files / 545,748 bytes | `project.test_command: cargo test --locked`; source-bound locked baseline; stable runtime candidates; latest dependency candidate; max 6 scenarios; 900 seconds each |

The executable configurations are frozen with this protocol and are part of
the release candidate inventory:

| Target | Config | SHA-256 |
|---|---|---|
| Python | [`external/python-jmespath.yml`](external/python-jmespath.yml) | `f73c70ac4ae589c60f9766abd36dd9834d3580b3617947a45be5f8686b84388a` |
| Node.js | [`external/node-commander.yml`](external/node-commander.yml) | `0836670fcae0067e47468fafeaf5fbb6f69ba768257ab33e0b98664779715783` |
| Rust | [`external/rust-fd.yml`](external/rust-fd.yml) | `61f07ae034d526e9b2430b7c9a7592aa83df1c0d3ad9991bca78d89475f36ffc` |

The immutable commits, owners, visibility, commit trees, and file modes were
read from the public GitHub API before execution. The Python commit tree is
`9c54fa72fc42fbef72011798bc3eba3610934541`, with requirements blob
`bf75ba9ff3a481785be98b99516ebd0194d02c50`. The Rust commit tree is
`f78511742956e238e7d6f405bd3ff8bab0e0f0fb`, with `Cargo.lock` blob
`bf18be4d08262f1484c207343d42a05ec50010cd`. Both repositories are public,
non-forks owned outside `taipei49314`; their recursive trees were complete and
contained only regular file/tree modes. Exact shallow checkouts additionally
passed strict Git object verification, contained no gitlinks, symlinks, LFS
pointers, or dirty files, and stayed within the declared size bounds. Execution
checks out each commit explicitly and scans the local checkout, so a moving
default branch cannot silently replace the registered source.

Exclusions were fixed before execution: repositories owned by the project
owner, TomorrowCI fixtures or purpose-built breakage demos, projects requiring
host execution, private dependencies or credentials, submodules/LFS, and
projects exceeding the declared scenario/time budget. A registered target is
not replaced merely because its result is unfavorable; any operationally
necessary replacement must retain the original evidence and a written reason.

Each project-operated run must use the frozen candidate binary and retain:

- raw run and scenario bundles;
- `scan`, `verify`, and recorded-manifest `replay` exit codes;
- source/config/engine/image identities and evidence hashes;
- workflow URL and candidate artifact digest;
- every failure, block, unsupported result, or replacement rationale.

The repository-owned `external-targets.yml` workflow performs those three
pre-registered runs from hardened exact-SHA local checkouts, verifies the
candidate provenance, seals and reads back each result artifact, and emits a
combined project-operated result. These records are valuable operational
evidence but are always classified as project-operated; that workflow cannot
set or satisfy the independent result field.

## Independent trust root

At least one repository maintainer must invoke the immutable candidate from a
repository they control, or an auditor uninvolved in this implementation must
download it in an independent checkout/environment and publish a complete
result. The result may honestly observe no horizon or a target failure. A tool
crash, required `BLOCKED`, identity failure, or unverifiable replay does not
pass the operational gate.

Independent evidence must use a **public immutable GitHub Release**, not a
cross-repository Actions artifact. A `GITHUB_TOKEN` is scoped to the repository
that issued it, so the TomorrowCI release workflow deliberately does not use
its token to fetch an auditor's repository or artifact. No broad personal
access token is accepted as a substitute. The auditor publication contract is:

1. Run from a public repository owned by the declared auditor, on a
   GitHub-hosted runner, and retain the canonical public Actions run URL, exact
   workflow path, run attempt, and workflow source SHA.
2. Choose a restricted release tag and asset name matching
   `[A-Za-z0-9][A-Za-z0-9._-]*`; the recommended forms are
   `tomorrowci-independent-qualification-<candidate-manifest-sha256>` and
   `tomorrowci-independent-evidence.zip`. The tag and asset name are part of
   the attested qualification subject before publication.
3. Attest the canonical `qualification-result.json` in the auditor repository
   and obtain its GitHub attestation bundle. Place both
   `qualification-result.json` and
   `qualification-result.attestation.jsonl` at the ZIP root alongside the raw,
   sealed evidence, replay receipts/logs, and the declared sealed scenario
   result. The bundle is required so verification can be performed offline
   without credentials for the auditor repository.
4. Enable GitHub immutable releases for the auditor repository. Create a draft
   release whose exact `target_commitish` is the workflow source SHA, attach
   the completed ZIP, and publish it only after all assets are present. Its tag
   must be a lightweight tag pointing directly to that same commit. Draft,
   prerelease, mutable, annotated-tag, branch-targeted, or replaceable assets
   do not qualify.
5. Read back the public release, release-asset, and Git-tag REST endpoints and
   freeze their positive numeric release/asset IDs, exact tag, canonical
   release URL, canonical `releases/download/<tag>/<asset>` URL, and the
   lowercase SHA-256 digest reported by GitHub into the independent result.
   The downloaded ZIP SHA-256 must match that same frozen digest.

Qualification re-fetches all independent repository, Actions run, release,
asset, and tag metadata through unauthenticated HTTPS-only requests. It
requires `immutable: true`, a published non-prerelease, exact release and asset
IDs/URLs, GitHub's matching asset digest and byte size, and a lightweight tag
at the declared workflow source commit. Transfer is time- and size-bounded and
permits only HTTPS redirects. The validator requires the complete raw package:
an exactly inventoried sealed run and scenario, exactly two exactly inventoried
detached receipts bound to the same original attempt, both replay logs and exit
records, and the replay-pair binding. It safely extracts that already-validated
package into a new directory, performs offline `gh attestation verify` bound to
the auditor repository, exact signer workflow, exact workflow source SHA, and a
GitHub-hosted runner, then uses the frozen candidate binary to `verify` the
original run, `verify` both receipts, and `replay-qualify` that exact pair. Any
redirect outside HTTPS, missing API field or raw member, expired or mutable
transport, digest/inventory mismatch, unsafe ZIP member, missing bundle, or
identity mismatch fails closed.

The implementer, another agent, another account of the implementer, and
project-owned CI are not independent. Until a qualifying result is published,
`EXTERNAL_EVIDENCE_INDEX.json` stays `BLOCKED_EXTERNAL` and no stable tag is
authorized.
