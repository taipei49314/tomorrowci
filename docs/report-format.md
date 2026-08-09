# Report format

## Evidence directory

```text
.tomorrowci/runs/<run-id>/
  run.json
  repository.json
  config.normalized.json
  plan.json                         # when emitted for this run status
  candidates.json                   # when emitted for this run status
  verdicts.json
  frontier.json
  report.html                       # when emitted
  report.json                       # when emitted
  report.sarif                      # when requested
  checksums.txt                     # v1 sealed inventory for the whole run
  scenarios/<scenario-id>/
    scenario.json
    environment.json
    commands.json
    stdout.log
    stderr.log
    result.json
    failure-signature.json          # only when a signature exists
    replay-manifest.json
    replay.sh
    replay.ps1
    checksums.txt                   # v1 sealed inventory for this scenario
```

The run-level inventory covers the complete recursive regular-file set below the
run directory. That includes scenario files and each scenario's own
`checksums.txt`. Only the inventory file that is doing the listing is excluded
from its own entries.

## Sealed inventory v1

`checksums.txt` is a strict, versioned SHA-256 inventory. A run inventory starts
with this exact header (scenario and generic bundles substitute their own
`kind`):

```text
# tomorrowci-evidence-checksums-v1 kind=run algorithm=sha256 scope=recursive sealed=true
```

Every following line has this grammar:

```text
<64 lowercase hexadecimal SHA-256 characters>  <canonical relative path>
```

There are exactly two spaces between the digest and path. The entire file uses
LF only (any CR is rejected), every record is LF-terminated, and the file must
end with a final LF. Records contain no blank lines and are sorted by ascending
path. Duplicate paths and an entry for the inventory's own `checksums.txt` are
rejected.

Bundle kinds also enforce a minimum layout:

| Kind | Required inventoried paths |
|---|---|
| `run` | `config.normalized.json`, `frontier.json`, `repository.json`, `run.json`, `verdicts.json` |
| `scenario` | `commands.json`, `environment.json`, `replay-manifest.json`, `replay.ps1`, `replay.sh`, `result.json`, `scenario.json`, `stderr.log`, `stdout.log` |
| `generic` | No TomorrowCI-specific required filenames |

Conditional files are still integrity-protected whenever present. A verifier
compares the recursive regular-file set with the inventory in both directions:
a listed file that is missing, an unlisted extra file, or a digest mismatch all
fail verification. Directories are traversal containers rather than hashed
entries, so empty directories do not affect the file-set comparison.

### Canonical path and entry protections

Each inventoried path must be UTF-8, relative to the bundle root, non-empty, and
written with `/` separators. Leading or trailing whitespace, absolute paths,
drive/alternate-stream `:`, backslashes, NUL, empty components, `.` components,
and `..` components are rejected. Every component also rejects a trailing dot
or space and the case-insensitive Windows DOS device stems `CON`, `PRN`, `AUX`,
`NUL`, `COM1` through `COM9`, and `LPT1` through `LPT9`, including names with an
extension such as `CON.txt`. Run IDs and scenario IDs used by the evidence store
must additionally be a single component. Paths that collide after portable
case folding (for example `A.json` and `a.json`) are rejected so a bundle has
the same identity on case-sensitive and case-insensitive filesystems.

At its root, traversal, inventory, hashing, and verified-read checkpoints, the
verifier uses link-aware metadata and rejects any observed symbolic link,
Windows reparse point, or other non-regular entry. It also rechecks the file set
and inventory after hashing and rejects changes observed during the
verification pass. These checks are not an atomic filesystem snapshot and do
not claim to defeat every malicious concurrent pathname swap; do not verify or
consume a bundle while another process can modify its directory tree.

An old, unversioned `checksums.txt` is not accepted as equivalent evidence. It
fails closed as `UnsealedLegacy`; migration must create and retain a newly
sealed bundle rather than silently treating the historical checksum list as v1.

### Typed identity checks

After the exact bytes verify, `run` and `scenario` bundles are parsed through
fixed Serde schemas. A run must bind its run ID, normalized-config digest,
repository snapshot, embedded frontier, completion timestamps, status,
scenario count, optional execution plan, verdicts, evidence references, and
nested scenario inventories consistently. A scenario must bind its directory,
scenario/result/replay IDs, image tag and digest, commands, workdir, resource
limits, network mode, and a nonzero final-result attempt bounded by the verdict's
attempt count. v1 does not preserve every rerun as separate attempt evidence;
that proof remains a later format addition. Duplicate identities,
dangling evidence references, mixed run/scenario IDs, and cross-mixed image or
command records fail closed. A `generic` bundle intentionally has no
TomorrowCI-specific semantic model and receives exact-set integrity checks only.

### Resource and consumption bounds

Verification rejects an inventory larger than 16 MiB, more than 10,000 bundle
entries (files plus directories), nesting beyond 64 directories, or more than 2 GiB of inventoried file
bytes. An individual read through a verified bundle is capped at 64 MiB, and a
typed JSON document is capped at 16 MiB. These are fail-closed format limits,
not container-execution resource settings.

The high-level `EvidenceStore` permits one final seal. Once its inventory
exists, further writes and a second `finalize_checksums` call fail closed. The
lower-level `seal_bundle` API remains available for explicit migration and
forensic tooling; normal producers must complete every writer before the one
finalization step.

A successful verification returns a `VerifiedBundle` that retains the parsed
inventory generation. Later `read_bytes` and `read_json` calls locate a path in
that retained inventory and hash the bytes again against its retained digest;
they do not silently switch to a newly written `checksums.txt`. This binds
consumption to the verified inventory generation, subject to the non-atomic
filesystem limitation above.

### Sealed report identity

When a run config enables `report.html`, `report.json`, or `report.sarif`, the
file is required inside the run inventory. The verifier builds the report model
from the sealed `run`, verdict, frontier, plan, and candidate records,
deterministically renders the enabled format, and requires an exact byte match.
HTML and SARIF use the sealed run's `tool_version` for their embedded renderer
version; JSON is the deterministic serialized model.

This is a byte-compatibility contract with the report renderer implemented by
the verifying binary, not an unlimited promise that every future renderer can
reproduce every historical template. An incompatible future template or schema
change must retain a compatible renderer or introduce an explicit format/
inventory version boundary before it can verify older sealed report bytes.

## `verify` command contract

```bash
tomorrowci verify <run-id|run-path>
tomorrowci --evidence-root /path/to/evidence verify <run-id>
```

An absolute path or a selector containing a path separator (for example
`./downloaded-run`) is an explicit filesystem path; TomorrowCI verifies that
directory directly. Both explicit paths and bare run IDs must verify as a
`run` bundle; a self-declared `scenario` or `generic` bundle is rejected. A bare
selector is always one run ID under `<evidence-root>/runs/`. This prevents a
current-directory entry from silently shadowing a requested run ID.

On success, `verify` writes one line to stdout and exits `0`:

```text
PASS version=1 kind=run file_count=<count> root=<JSON-quoted-path>
```

A missing bundle, legacy/unversioned or unsupported inventory, malformed
record, unsafe or duplicate path, missing/extra file, non-regular entry, digest
mismatch, invalid typed JSON, cross-file identity mismatch, invalid run/scenario
semantics, or detected concurrent change is a verification failure: no `PASS`
line is emitted and the command exits `1` with the error on stderr. CLI syntax
or argument-parsing errors are Clap usage errors and exit `2`.

`verify` is deliberately non-executing. It parses the inventory, hashes regular
file bytes, and validates fixed typed JSON relationships; it does not execute
`replay.sh`, `replay.ps1`, recorded commands, target code, or containers, and it
does not equate an internally consistent record with a successful replay.

A `PASS` therefore establishes byte integrity and internal identity consistency
relative to the co-located v1 inventory. It does not authenticate who produced
the bundle, prove the truth of its claims, or prove even one replay execution.
In particular, it does **not** yet provide the two successful replay attempts
required by the Phase 1 acceptance criteria; those attempts need separate
execution evidence.

## HTML

Self-contained file generated from **real** run JSON. Views:

1. Horizon timeline
2. Scenario matrix
3. Failure evidence + replay
4. Planner/execution graph

Accessibility: semantic landmarks, table headers, visible focus, text badges
(not color alone), `prefers-reduced-motion`.

## SARIF

Optional `report.sarif` maps `FUTURE_FAIL` / `BASELINE_INVALID` to SARIF results
(`tomorrowci/future-fail`).
