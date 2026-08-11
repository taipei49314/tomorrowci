# Patch Lab

Patch Lab tests a proposed source patch without changing the original source or
its sealed run. It is a qualification pipeline, not an automatic merge tool.
Target code still runs only through TomorrowCI's container sandbox.

## Run a proposal

Start from a verified v2 run and an exact source tree matching that run's
`source-manifest.json`:

```console
tomorrowci patch propose RUN_ID \
  --source ./exact-source \
  --patch ./proposal.patch \
  --evidence-root ./.tomorrowci
```

The command:

1. verifies the original run and re-hashes the supplied source tree;
2. validates the exact patch bytes and copies the inventoried source files into
   a new disposable workspace;
3. runs `git apply --check` and applies the patch only in that copy;
4. runs the normal container scan, including baseline and planned future
   scenarios, then verifies the resulting sealed v2 run;
5. exact-replays every patched scenario in a fresh disposable workspace and
   writes each execution as an independent sealed v2 replay-attempt bundle;
6. re-verifies that the original run inventory and source tree did not change;
7. seals `patch-proof.json`, the exact `proposal.patch`, the complete original
   and patched bytes of every changed file under `source-witness/`, and the
   replay-attempt bundles under a separate exact-set inventory.

The whole-file witness is deliberate: a source SHA-256 plus the partial context
in a unified diff is not sufficient to prove the resulting source SHA-256.
Patch Lab limits the combined witness to 16 MiB, requires UTF-8, and blocks
secret-like content rather than copying it into public evidence.

The proof is written below `.tomorrowci/patches/`. The patched scan remains a
normal run below `.tomorrowci/runs/`. Exit code `8` means a valid proof was
created but its disposition is non-green; a `BLOCKED:` setup or safety failure
uses exit code `4`.

## Patch input boundary

Patch Lab accepts UTF-8 unified diffs up to 1 MiB and 128 changed files. It
rejects:

- absolute paths, `..`, backslashes, drive-qualified paths, control characters,
  case-insensitive duplicates, and non-portable Windows device names;
- `.git`, `.tomorrowci`, dependency/build-cache directories, and paths whose
  existing component is a symlink or Windows reparse point;
- binary patches, submodule or symlink modes, renames, copies, mode-only
  changes, combined diffs, and ambiguous quoted/spaced Git paths;
- secret-like values that would be unsafe to persist in a public proof bundle.

These restrictions make the validator and `git apply` agree on every target.
The exact bytes are copied to a verifier-owned staging file before either the
check or apply step, preventing the input file from being swapped after
validation.

## Dispositions

- `QUALIFIED` requires an observed breakage in the original run, an unchanged
  original, the same normalized configuration, the exact same sealed scenario
  identity changing from a failing verdict to a passing verdict, a different
  patched source tree, a completed patched run, a passing baseline, at least one
  passing future scenario, and successful sealed exact replay for every patched
  scenario.
- `PROPOSAL` is non-green. It covers useful but insufficient evidence, including
  a still-failing scenario, failed replay, missing future scenario, or an
  original run with no observed breakage to repair.
- `BLOCKED` is non-green. It covers a changed original, a blocked patched scan,
  or a configuration identity mismatch.

Patch Lab never promotes a proposal merely because the textual diff applied.

## Verify a downloaded proof

Supply verifier-chosen paths for all three bundles:

```console
tomorrowci patch verify \
  --proof ./patch-proof \
  --original-run ./original-run \
  --patched-run ./patched-run
```

The verifier does not execute target code and never follows paths stored in the
proof. It recomputes both run bindings, source/config/verdict hashes, patch
summary and SHA-256, scenario exact-set inventories, replay-manifest identities,
and every nested replay-attempt inventory and outcome. It requires the complete
source-manifest delta to be exactly the patch's path/kind/mode set, binds every
changed-file witness to the corresponding manifest entry, applies the sealed
patch with Git in a fresh verifier-owned temporary directory, and compares the
resulting bytes to the patched witnesses. It separately reloads the original
frontier scenario and patched scenario and requires their canonical identities
to match before accepting a fail-to-pass repair. The final disposition and
reason are recomputed, so an attacker cannot qualify an unrelated successful
run by self-resealing the directory. Verification requires Git but does not run
any target command.

`PatchProof` is evidence of this bounded execution. It is not a code-review
approval, maintainer signature, or authorization to write to the original
repository.
