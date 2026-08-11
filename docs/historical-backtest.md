# Historical registry-snapshot backtests

`tomorrowci backtest` never presents a current-registry install as historical.
Each sampled Git commit must have a strict snapshot for the commit's UTC
calendar date. Missing material is `INCONCLUSIVE`; inconsistent, unsafe, or
tampered material is `SCHEDULED_RISK`. Both are non-green (CLI exit code 7).

Historical source is materialized from raw Git objects, not checkout/archive
filters. This v0.2 boundary accepts only regular `100644`/`100755` blobs with
portable ASCII paths and blocks links, gitlinks, special modes, reserved
Windows aliases, ambiguous case, and oversized trees. A host that cannot
preserve a committed executable bit fails closed for that point.

```text
tomorrowci backtest ./repository \
  --at 2026-01-15 --until 2026-01-15 \
  --snapshot-registry ./registry-snapshots
```

The registry layout is fixed:

```text
registry-snapshots/
  python/2026-01-15/snapshot-manifest.json
  python/2026-01-15/payload/...
  node/2026-01-15/snapshot-manifest.json
  node/2026-01-15/payload/...
  rust/2026-01-15/snapshot-manifest.json
  rust/2026-01-15/payload/...
```

## Strict manifest v1

Unknown JSON fields are rejected. `files` is a strictly sorted, unique, exact
recursive inventory; paths must be portable relative UTF-8 paths. Symlinks,
Windows reparse points, special files, traversal, DOS device names, trailing
dot/space components, case-fold-equivalent collisions, missing/extra files,
size mismatches, and SHA-256 mismatches fail closed. The manifest is capped at
1 MiB. Payload file-count and byte caps are configurable, defaulting to 20,000
files and 2 GiB.

`snapshot_id` is SHA-256 over the ordered semantic fields, excluding the ID
itself. Each UTF-8 field is framed as an unsigned 64-bit big-endian byte length
followed by its bytes. The domain separator is
`tomorrowci-registry-snapshot-v1`; fields then follow manifest order, with each
file contributing `path`, `sha256`, and decimal `size` in sorted order.

```json
{
  "schema_version": 1,
  "snapshot_id": "sha256:<content address of every semantic field below>",
  "ecosystem": "python",
  "effective_at": "2026-01-15T12:00:00Z",
  "captured_at": "2026-01-15T13:00:00Z",
  "source": {
    "url": "https://pypi.org/simple/",
    "immutable_revision": "sha256:<immutable upstream capture revision>"
  },
  "resolver_mode": "python_wheelhouse",
  "files": [
    {
      "path": "example-1.0-py3-none-any.whl",
      "sha256": "<64 lowercase hex>",
      "size": 1234
    }
  ]
}
```

Allowed ecosystem/resolver pairs are:

| Ecosystem | Resolver mode | Sandboxed resolver contract |
|---|---|---|
| Python | `python_wheelhouse` | pip `--no-index --find-links /workspace/.tomorrowci-backtest/registry-snapshot/payload` |
| Node | `npm_offline_cache` | npm `--offline --cache /workspace/.tomorrowci-backtest/registry-snapshot/payload` |
| Rust | `cargo_vendor` | Cargo `--offline` with a `source.crates-io` replacement pointing at `/workspace/.tomorrowci-backtest/registry-snapshot/payload` |

The snapshot is verified, copied into the disposable source export at the
reserved `.tomorrowci-backtest/registry-snapshot` path, and
verified again. Adapter environment and command output is still passed through
the normal safety validators. Every snapshot-backed command has
`network_required=false`, and the sandbox environment uses `network_mode=none`.
The configured network value is applied only as a non-expanding upper bound, so
the historical adapter's stricter `none` cannot be weakened by the default
`fetch-only` setting. The engine must confirm no attached network before target
commands execute; a Docker/Podman status, connect, or disconnect error is
`BLOCKED`, not evidence of offline execution.

## Evidence binding

The normal run remains sealed and immutable. After it verifies, TomorrowCI
creates a separate, self-contained sealed
`backtests/<commit>-<proof>/` proof bundle that binds:

- original source repository and exact commit/time;
- snapshot content address, manifest hash, effective/capture time, source URL
  and immutable source revision;
- normalized config SHA-256;
- canonical source-manifest, run-manifest, verdict-set, and frontier SHA-256;
- a recomputed `QUALIFIED` or `SCHEDULED_RISK` outcome;
- exact runtime image references and digests from sealed scenario evidence;
- strict offline identities and `network_used=false` in every original and
  replay attempt receipt;
- run ID and the sealed run inventory SHA-256.

The bundle carries `witness/run`, an independently sealed v2 run,
`witness/registry-snapshot`, the exact manifest and payload, and a strict
`witness/git-source-binding.json` that records the full commit, Git tree, and
commit-only source-manifest identity. The outer recursive inventory covers all
three witnesses. Readback removes the reserved snapshot subtree from the run
source manifest and recomputes the commit-only identity. A JSON file that
merely names hashes and is then self-resealed is therefore not a valid
BacktestProof.
TomorrowCI deliberately does **not** copy repository bytes into the detached
proof: that would silently publish proprietary source or secrets. The sealed
run's typed source manifest binds the commit claim and source-tree hashes, but
source bytes remain with their owner.

Each exported commit's `.tomorrowci.yml` is loaded when present; otherwise the
versioned defaults are used. Backtest resource caps override only the bounded
scenario counts. The normalized effective config hash is sealed in both the run
and detached proof.

The report links the proof directory, canonical proof SHA-256, and sealed proof
inventory SHA-256. No field is injected into an already sealed run.

After downloading a proof directory, run:

```bash
tomorrowci backtest-verify <proof-directory>
```

This non-executing readback verifies the outer recursive inventory and embedded
run inventory, then re-parses and re-hashes the run, config, verdicts, frontier,
scenario results, source manifest, snapshot manifest, and complete snapshot
payload. Every available typed cross-link, commit/date relationship, derived
outcome, runtime-image set, recorded `network_mode=none`, command network flags,
and all attempt `network_used=false` values must agree. It prints the derived proof and
inventory SHA-256 values on success. Because repository bytes are intentionally
absent, readback does not independently reconstruct or authenticate the source
tree named by the sealed source manifest. Producer authenticity and the
source-manifest claim still depend on an independently trusted publication or
attestation.

## Fixtures and acceptance

`fixtures/backtest-snapshots` contains bounded snapshots with one real pinned
local dependency for each ecosystem: a Python wheel, an npm package tarball,
and a Cargo vendor directory. They do not claim to recreate a public registry.
`scripts/ci/generate-backtest-fixtures.py` deterministically regenerates the
package artifacts and exact manifests. Unit tests verify their content
addresses and exact sets. Adapter fake-executor tests reject network-enabled
commands, host paths, and non-`/workspace/...` snapshot paths. The live CI
acceptance installs/builds all three dependencies with networking disabled,
asserts a dependency-provided marker in the sealed logs, and independently
reads back each self-contained proof.

Without `--snapshot-registry`, the old command shape remains accepted, but all
sampled points are honestly `INCONCLUSIVE` and the command is non-green.
