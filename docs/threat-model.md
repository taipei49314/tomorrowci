# Threat model

## Scope

TomorrowCI is a local CLI that executes untrusted repository code through a
container engine and stores run evidence on the host. This model separates the
container-execution boundary from the evidence-consumption boundary. The
supported v1 sealed inventory protects evidence integrity and internal typed
identity at rest. v2 adds source-snapshot identity, strict exact-replay inputs,
per-attempt receipts, and verifier-recomputed replay qualification. Both
versions remain unsigned project-produced evidence rather than producer
authentication or independent attestation.

## Assets

- Integrity of **verdicts and evidence** (must not lie)
- Confidentiality of **host secrets** (tokens, keys, env)
- Integrity of the **user's repository** (must not be mutated)
- Availability of the **host** (CPU/memory/disk from runaway builds)
- Integrity of replay inputs consumed by later `show`, `explain`, `policy`,
  `compare`, `report`, and `replay` operations

## Trust boundaries

| Zone | Trust |
|---|---|
| TomorrowCI binary + host config | Trusted |
| Container engine (Docker/Podman) | Trusted TCB |
| Target repository code & dependencies | **Untrusted** |
| Container images from registries | Partially trusted (pin digests when possible) |
| Evidence bundle on disk or received from another party | **Untrusted until its expected-kind supported v1/v2 inventory verifies** |
| Generated HTML reports | Untrusted content, must be escaped |

The evidence boundary is filesystem-based: an untrusted directory and its
co-located `checksums.txt` cross into TomorrowCI's evidence consumers. The
verifier parses the inventory, hashes file bytes, and validates fixed typed
evidence relationships. It does not execute recorded bundle content.

## Attacker capabilities and goals

A target repository, dependency, compromised image, or local process with
write access to an evidence directory may try to:

1. Escape the container and access host files or secrets.
2. Exfiltrate CI secrets via network during tests.
3. Mutate, delete, add, redirect, or race evidence files to hide a future break
   or invent one.
4. Supply traversal paths, symlinks, Windows reparse points, or special files so
   verification reads outside the bundle or blocks on attacker-controlled I/O.
5. Abuse TomorrowCI as a free compute/network botnet.
6. Inject active content through malicious test logs in HTML reports.

An attacker without the ability to alter the TomorrowCI binary or the already
trusted inventory cannot make changed bytes retain the inventoried SHA-256
digest under the current cryptographic assumptions. An attacker who can replace
both a bundle and its unsigned inventory is explicitly still in scope as a
residual provenance risk.

## Mitigations

| Control | Implementation and evidence |
|---|---|
| No host execution by default | Sandbox-only execution path; `doctor` / `scan` block without an engine. |
| No privileged containers | Never pass `--privileged`. |
| No docker.sock mount | Explicitly reject paths containing `docker.sock`. |
| Env isolation | Do not forward host env; forbid secret-like keys. |
| Disposable workspace | Copy/worktree; skip following symlinks on copy. |
| Resource limits | Memory, CPU, PID, and wall-clock limits. |
| Network split | Fetch may use network; tests use `network=none`. |
| Log redaction and caps | Redact API-key patterns and cap stdout/stderr before writing scenario evidence. |
| HTML escaping | Escape untrusted strings in generated reports. |
| Versioned exact-set inventory | [`BundleInventory::parse` and `verify_bundle`](../crates/evidence/src/lib.rs) require an exact supported v1/v2 header and canonical, sorted SHA-256 records using LF only and a mandatory final LF; missing, extra, duplicate, malformed, and digest-mismatched files fail closed. Historical unversioned checksum lists return `UnsealedLegacy`. |
| Required layout and expected kind | Run and scenario kinds require their version-specific security-relevant core files; v2 also defines a `replay-attempt` kind. Evidence-store consumers require a `run` inventory instead of accepting a self-declared `generic` bundle. |
| Typed identity consistency | Run/config/repository/frontier/plan/verdict links and scenario/result/replay/image/command/resource identities are parsed from fixed schemas and checked across files. v2 also binds the exact source, configuration, scenario, image digest, environment, commands, engine, attempts, and qualifications. Dangling, duplicate, or mixed identities fail closed. |
| Path confinement | [`validate_inventory_path`](../crates/evidence/src/lib.rs) rejects absolute and drive/alternate-stream paths, backslashes, NUL, leading/trailing whitespace, empty, `.` or `..` components, trailing component dots/spaces, case-insensitive DOS device stems (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, including extensions), and portable case-fold collisions. Run and scenario IDs are one component. |
| Symlink and special-file rejection | Root, traversal, inventory, hashing, and verified-read checks use link-aware metadata. Any symlink, Windows reparse point, or non-regular entry observed at those checkpoints is rejected. |
| Verify before consume | [`open_verified_store`](../crates/runner/src/lib.rs) gates `show`, `explain`, `policy`, `compare`, and `replay`; [`report`](../apps/cli/src/main.rs) also verifies before loading evidence. |
| Source-bound exact replay | v2 hashes the captured source file set and tree, retains every original attempt, and executes qualifying scan-time replays in fresh disposable workspaces against the recorded digest-pinned image. The verifier recomputes receipt digests and equivalence; an observed frontier requires at least two distinct consecutive equivalent replay receipts. |
| Mount fail-closed boundary | The primary project copy is the implicit `/workspace` mount. Explicit host mounts are rejected as `BLOCKED` until their semantics can be reproduced safely; generalized workdir/mount handling is not claimed. |
| Generation-bound reads | A `VerifiedBundle` retains the inventory it verified. Consumer reads locate entries in that retained inventory and re-hash bytes against the retained digest, so they cannot silently adopt a later independently sealed generation. |
| Deterministic sealed reports | Enabled HTML, JSON, and SARIF files are rebuilt from the verified evidence model and compared byte for byte. HTML/SARIF embed the sealed `tool_version`; incompatible future renderer changes require a compatibility implementation or a new format/version boundary. |
| Evidence resource bounds | Verification caps inventories at 16 MiB, bundles at 10,000 filesystem entries, nesting at 64 directories, total inventoried bytes at 2 GiB, verified reads at 64 MiB, and typed JSON at 16 MiB. |
| Finalize once | The high-level `EvidenceStore` rejects writes and a second finalization after `checksums.txt` exists. Normal producers finish all scenario, manifest, and report writers before one final seal. |
| Non-executing verification | [`tomorrowci verify`](../apps/cli/src/main.rs) parses supported inventories and fixed typed evidence schemas. For v2 it recomputes the sealed replay qualification, but does not run replay scripts, recorded commands, target code, or a container. |
| Detected-change rejection | The verifier re-enumerates the file set, rereads the inventory, and checks file metadata around hashing; changes and link/reparse entries observed at those checkpoints fail closed. |

## Known limitations (residual risk)

- The co-located v1/v2 inventory is unsigned. SHA-256 detects changes relative
  to that inventory, but does not authenticate its producer or stop an attacker
  who can replace both evidence and inventory. Signed provenance remains future
  work.
- A v1 `PASS` is integrity and typed-identity evidence only. A v2 `PASS` also
  confirms that its sealed source, attempts, and recomputed qualification are
  internally consistent; it does not prove the producer actually performed the
  work or provide an independent trust root.
- Public post-seal `replay` executes from verified evidence in a fresh workspace
  but does not append a receipt or mutate the sealed run. That execution cannot
  later be cited from the bundle as an additional qualified attempt.
- Explicit host mounts currently fail closed as `BLOCKED`; only the implicit
  `/workspace` project mount is supported, and generalized sandbox workdir/mount
  reproduction remains future work.
- Filesystem checks are fail-closed for changes, links, and reparse points they
  observe, but do not create an atomic filesystem snapshot or prove resistance
  to every malicious concurrent pathname swap between syscalls. Avoid
  concurrent writers and retain immutable copies for qualification evidence.
- Container breakout vulnerabilities in the engine/kernel remain in the TCB.
- Base images or registries may be malicious or compromised.
- `fetch-only` still allows network during dependency installation.
- A non-root container user and read-only root filesystem are not always
  possible while package managers install dependencies.
- v0.1 relies on engine-default seccomp/AppArmor plus
  `no-new-privileges`; it does not install a custom profile.

## Phase 1 claim boundary

v1 remains the legacy integrity and typed-identity foundation. v2 adds the
source manifest, strict replay identity, all original attempts, and two-or-more
scan-time exact replay receipts with verifier-recomputed qualification. This is
still not a claim that Phase 1 is complete: post-seal replay receipts, generalized
workdir/mount execution, independent adoption/audit evidence, and other open
qualification gates remain outside the implemented proof.

## Out of scope (v0.1)

- Multi-tenant SaaS isolation
- Formal verification of the planner
- Guarantees against intentional flaky sabotage beyond classification
- Evidence authenticity, signatures, and third-party provenance

## Reporting

See [SECURITY.md](../SECURITY.md). The inventory and CLI contract are specified
in [Report format](report-format.md).
