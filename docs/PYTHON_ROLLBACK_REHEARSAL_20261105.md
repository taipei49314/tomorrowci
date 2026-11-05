# Python rollback rehearsal — 2026-11-05

The rollback workflow repaired one natural batch update and replayed the repair.
This rehearsal does **not** establish lower preparation or human effort than a
local CI matrix plus an AI operator. Native uv lock integration remains missing.

## Frozen case

The original historical pair from [dynamic-typer Renovate PR 14](https://github.com/rcmdnk/dynamic-typer/pull/14)
is `ebde45408b57dd020c1f0af2d706cfa226560a04` →
`f0c20dfc664c5917494a24267a2a896122e01bc7`. Only `uv.lock` changed.
Original historical CI runs are unavailable; current local execution establishes
the results, not another rebased pair's preserved CI.

Seven lock-level updates become six installed updates on Linux / Python 3.11.
All arms preserve the complete 88 third-party distributions plus the project and
the original 13 tests. Before passes; after repeatedly fails the same five tests.
Rolling Click 8.2.0 back to 8.1.8 repairs the suite while retaining the other five
installed updates. Exceptiongroup's lock-only update is also preserved.

Target image: `sha256:b2b58ecbf8ab17e683346a1f6445ad0d1c10b0d18244d82b420ae7bcea21cd05`.
Python 3.11.18, uv 0.13.6, Node 20.20.2, Git 2.47.3. Mutable historical build
tooling was replaced with explicit shared build pins and offline artifacts;
this is a present-day reproduction, not an exact reconstruction of deleted CI.
Host: LAPTOP-01AGNPJU, `HUMAN_AUTHORIZED_LOCAL_PJU_NOT_EC_POOL`.

## Outcomes

| Arm | Complete test invocations | Deliverable and limitation |
|---|---:|---|
| TomorrowCI | 39 across 16 valid environments | Verified same-failure reduction and full-complement repair with fresh replay; hashed requirements, not a native uv.lock patch |
| Local matrix + AI | 6 across 3 environments | Click-only native lock patch; initial validation and fresh source/venv replay both pass |
| depsect 0.5.0 | 7 across 3 valid environments, plus 3 invalid generated locks | Native safe patch validates and replays, but all three native failing trials are lock parse errors, not the original test failure |

TomorrowCI source: `6cab59a57267d079c5cf7e7a7f9b58cfe5d30451`.
Diagnosis `645c5c198d40`, rollback validation `680a33917801`, replay attempt 1.
The 39 invocations comprise 36 diagnosis tests, two validation tests and one
fresh replay. Independent raw JUnit/inventory checks establish the same 13 IDs
and exact expected 89-version closure throughout. This external case audit is
stronger than the general `VERIFIED_COMMANDS_PASS` command-success claim.

Depsect source: [`972ec42`](https://github.com/LilVi02/depsect/tree/972ec42fbe38c3d145317eaebc31044048f3a9c3).
Its unchanged-version Typer dependency block conflicts with multiple Click
records in generated locks: `Dependency click has missing source field but has
more than one matching package`. The safe patch passes separately, but also
changes unrelated marker metadata; no cross-Python equivalence is claimed.

The matrix AI operator received neither the culprit nor other arms' findings.
It inspected its own logs, lock diff and official Typer release notes, then
validated one candidate. Its native patch SHA256 is
`4be9ce1a5f24746fd5b754b85b4626cbab3a1f5d53e254395e6fddf79ae6b17d`;
repaired uv.lock SHA256 is
`7a5594386bda560bea3a6f9148e27ba917c31e732ff207d7bde0acccafc1607f`.

## Preparation and interpretation

TomorrowCI needs full resolved hashed pins and wheel inputs; uv-native arms
consume the original Git/lock pair. Shared benchmark preparation does not make
that conversion free for ordinary users. Its repair/source still contains the
original after uv.lock; hashed requirements are not a ready-to-use uv repair.

Two earlier TomorrowCI Windows attempts exposed image-ID handling, command-line
limits and parallel pytest output-order instability. The fixes are included in
the executed source; failed/inconclusive receipts are retained. Common setup v1
also failed to enforce all intended build pins, so every formal arm used v2.

Observed final windows: TomorrowCI 130.455 seconds for scan/verify/rollback/verify;
matrix approximately 111.36 seconds; depsect's native CLI 39.205 seconds, excluding
external validation and using a different failing oracle. Filesystem/cache
placement, installation mechanisms and concurrent waits differ. These are not
a controlled speed ranking. All human_minutes fields remain null.

This is a local matrix rehearsal, not a GitHub Actions UI/queue comparison.
Actions were not enabled for this phase. No merge or release is implied.

## Product checks and next acceptance boundary

The executed source passes 225 Rust tests, clippy, 22 importer tests, one
separately invoked Docker long-command test and five live rollback controls:
valid retained upgrade; second independent failure; installation conflict;
no retained upgrades; incomplete diagnosis. Exported evidence independently
passes `verify` and `verify-rollback` after relocation to Windows.

The useful next boundary is native uv input and a minimal native lock patch,
using existing test commands, with same-failure checks and complete repair
replay built in. Compare that complete handoff across more natural cases and
actual users before claiming effort saved. For this case, matrix + AI currently
has the more direct project-ready repair.

The local deliverable `outputs/tomorrowci-rollback-proof` contains raw runs,
artifact hashes, both patches, controller/build receipts and the independent
audit. These local artifacts are not published by this source commit.
