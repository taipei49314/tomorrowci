# Qualification baseline

Audit date: 2026-08-09 (Asia/Taipei)

This is a point-in-time record of inspected source, public GitHub Actions evidence, local checks, and the existing release. It is not a claim that TomorrowCI is 100% complete, production-qualified, independently adopted, or ready for a new release.

## Subsequent release-hardening qualification (2026-08-11)

[PR #3](https://github.com/taipei49314/tomorrowci/pull/3) merged as exact
default-branch commit
[`945f45862489d8777b0abb6c78366f3bf21146ad`](https://github.com/taipei49314/tomorrowci/commit/945f45862489d8777b0abb6c78366f3bf21146ad).
Its exact-SHA [default CI run `31463431860`](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860)
completed with all 14 required jobs successful:

| Gate | Public job evidence |
| --- | --- |
| Rust, MSRV, dependency audit | [rust 93691381164](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381164), [MSRV 93691381157](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381157), [audit 93691381149](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381149) |
| Schema, evidence negatives, web | [schema 93691381132](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381132), [evidence-negative 93691381193](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381193), [web 93691381108](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381108) |
| Linux, Windows, macOS Intel CLI | [Ubuntu 93691381203](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381203), [Windows 93691381196](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381196), [macOS Intel 93691381220](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381220), [Windows verifier 93691381163](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691381163) |
| Docker, Podman, Action | [container 93691849361](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691849361), [live Podman 93691849342](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691849342), [dogfood 93691849341](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691849341), [consumer 93691849373](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/job/93691849373) |

The two principal evidence artifacts were downloaded through the GitHub API and
read back independently:

- [`tomorrowci-ci-evidence` artifact 9090824623](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/artifacts/9090824623):
  1,093,530-byte raw ZIP; SHA-256
  `48ae2ac0523be682c9cccc12dc1d3aa0b5d720b510ef9b6befb0ca11122722ef`,
  matching GitHub's server digest.
- [`tomorrowci-live-podman-evidence` artifact 9090823667](https://github.com/taipei49314/tomorrowci/actions/runs/31463431860/artifacts/9090823667):
  851,550-byte raw ZIP; SHA-256
  `a9e349cd469e37eed5e1fbc93baeeabea7bf4636d793fbf020082ad66198141a`,
  matching GitHub's server digest.

Downloaded-byte verification passed for 13 sealed runs (seven Docker,
including the patched run, plus six Podman) and 24 create-only public replay
receipts. Ten deterministic receipt pairs recomputed as qualified; the two
flaky pairs returned the required fail-closed nonqualification. Three detached
offline backtest proofs and one `QUALIFIED` Patch proof also reverified. The
Rust registry witness retained its inventoried `.cargo-checksum.json`, closing
the hidden-file artifact boundary. The Podman artifact independently covered
106 inventories and 2,296 references with no missing, unlisted, or mismatched
files, and all 80 attempt records bound Podman 4.9.3 on Linux x86_64.

This closes the listed exact-SHA technical, product, and default-CI gates with
project-operated public evidence. It does **not** constitute a frozen release
candidate, completed project-operated external-target run, genuinely
independent adopter/auditor evidence, or authorization for a stable tag.

## Subsequent merged evidence-trust qualification (2026-08-11)

The historical baseline below remains unchanged. Two later evidence-trust changes
were merged, culminating in default-branch commit
[`5e17208851c4f01f984b7087a1c789b4fd782afa`](https://github.com/taipei49314/tomorrowci/commit/5e17208851c4f01f984b7087a1c789b4fd782afa).
Its exact-SHA default CI run
[`31445290798`](https://github.com/taipei49314/tomorrowci/actions/runs/31445290798)
completed successfully across `rust`, `windows-verifier`, `schema`,
`container-integration`, and `action-dogfood`.

The preceding merged PR head was independently downloaded from
[PR run `31316568858`](https://github.com/taipei49314/tomorrowci/actions/runs/31316568858).
Artifact
[`9039028300`](https://github.com/taipei49314/tomorrowci/actions/runs/31316568858/artifacts/9039028300)
was 595,911 bytes; its downloaded SHA-256 was
`b1353365f007d940b849d4573e263a4f7f216b4a02b364a1268f66954504fbc8`,
matching GitHub's published artifact digest.

- Six run bundles reverified with the merged default-branch binary as
  `PASS version=2 kind=run`: `2f959f60225a` (242 files), `71c8a2f5fbe9`
  (154), `71cfe110acff` (48), `73a40ade47c0` (225), `ba0481ea486c`
  (47), and `cebb057f2626` (136).
- Recursive inspection covered 94 v2 inventories and 2,080 listed hashes with
  zero missing, extra, or mismatched files.
- Twenty replay manifests used syntactically valid `sha256:<64 hex>` image
  digests.
- Eleven `FUTURE_FAIL` verdicts corresponded one-for-one with 11
  qualifications and 22 retained replay receipts. Every qualification
  recomputed as equivalent with no recorded mismatch.

This is durable project-operated fixture evidence for the evidence and exact
replay implementation. It does not satisfy the separate Podman, public
external-target, independent auditor/adopter, product-scope, candidate, or
stable-release gates.

## Repository identity and live state

| Item | Observed value |
| --- | --- |
| Repository | <https://github.com/taipei49314/tomorrowci> |
| Default branch | `master` |
| Kickoff audit SHA | `1f42003a561630164699f94f274727be23f2c1a8` |
| Live `master` SHA | [`1f42003a561630164699f94f274727be23f2c1a8`](https://github.com/taipei49314/tomorrowci/commit/1f42003a561630164699f94f274727be23f2c1a8) |
| Local `HEAD` / `origin/master` at branch creation | `1f42003a561630164699f94f274727be23f2c1a8` / `1f42003a561630164699f94f274727be23f2c1a8` |
| Working branch | `agent/evidence-trust-core` |
| Open issues / pull requests | `0` / `0` at audit time |
| GitHub authentication | `gh auth status` succeeded for `github.com` |

There was no default-branch drift from the kickoff SHA at the start of this work. The absence of open issues or pull requests is repository metadata, not evidence that the gaps below are closed.

## Public default-branch CI

The latest default-branch run inspected was [CI run 31185394369](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369). It completed successfully on exact SHA `1f42003a561630164699f94f274727be23f2c1a8`.

| Job | Result | Public evidence |
| --- | --- | --- |
| `rust` | PASS | [job 92888532977](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92888532977) |
| `schema` | PASS | [job 92888533038](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92888533038) |
| `container-integration` | PASS | [job 92889106516](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889106516), [measure step](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889106516#step:5:1) |
| `action-dogfood` | PASS | [job 92889107297](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/job/92889107297) |

These are job-level GitHub conclusions. In particular, the `rust` job runs `doctor` with `|| true`, so its green conclusion is not evidence that `doctor` itself passed.

The downloadable `tomorrowci-ci-evidence` artifact has ID [`8996743664`](https://github.com/taipei49314/tomorrowci/actions/runs/31185394369/artifacts/8996743664). Its raw ZIP was 186,485 bytes and hashed to `dfec205e46a4cf8d00d916ef3dc7a2f8a48329e4dc8a7134a14690dd6ed7cf60`, matching GitHub's published `sha256:` digest. After extraction, all 26 `checksums.txt` manifests were checked across 253 listed files: missing `0`, mismatched `0`.

That establishes download and listed-file integrity for this artifact. It does **not** establish an end-to-end replay or independent verification. This run invoked `measure all`, which invoked scans. Text such as `tomorrowci replay ...` is a suggested reproduction command in the output; it was not executed by this run. At this SHA the CLI has no `verify` subcommand.

### Six built-in fixture outcomes

The following statuses come from the public `container-integration` artifact and its claim ledger. Here, `PASS` means that the fixture matched its declared expectation; expected failing or flaky scenarios are not being relabeled as successful scenarios. The run used Docker 28.0.4 on project-operated GitHub infrastructure. It is not independent external-adoption evidence.

| Fixture | Evidence status | Run ID | Inspected outcome |
| --- | --- | --- | --- |
| `python-runtime-break` | PASS | `ef029be6b9d5` | 5 scenarios: baseline `BASELINE_PASS`; Python 3.10/3.11/3.12/3.13 locked `FUTURE_FAIL`; observed horizon Python 3.10 locked. |
| `baseline-fail` | PASS | `6a412adc66e6` | 1 scenario: `BASELINE_INVALID`; no horizon authorized. |
| `flaky-project` | PASS | `812ea6b0283a` | 1 scenario: `FLAKY`; no horizon authorized. |
| `python-dependency-break` | PASS | `7300e5a313ad` | 4 scenarios: baseline `BASELINE_PASS`; Python 3.12 locked `FUTURE_PASS`; Python 3.11 latest and combined case `FUTURE_FAIL` (`SIMULATED` dependency axis); observed horizon Python 3.11 latest. |
| `node-dependency-break` | PASS | `e326a0db4f72` | 6 scenarios: baseline `BASELINE_PASS`; Node 22/24 locked `FUTURE_PASS`; Node 20 latest and two combined cases `FUTURE_FAIL` (`SIMULATED` dependency axis); observed horizon Node 20 latest. |
| `rust-msrv-break` | PASS | `bc1bb22a1a4e` | 3 scenarios: baseline `BASELINE_PASS`; Rust 1.85/1.86 locked `FUTURE_FAIL`; observed horizon Rust 1.85 locked. |

The fixture suite recorded 51 passing infrastructure/fixture claims and no failing claims. The combined measure summary, including benchmark claims, recorded `PASS=56`, `FAIL=0`, `BLOCKED=0`, `NOT_RUN=0`, and `SKIP=0`. These counts apply only to the measured claim set in this run.

## Local source and web baseline

These checks ran from the clean baseline source on Windows. A command passing means that command completed as described; it does not substitute for missing container, cross-platform, replay, verification, release, or external gates.

| Command / check | Result | Detail |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | Exit 0. |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | Exit 0. |
| `cargo test --workspace` | PASS | 52 tests across the observed test groups: `2+3+1+37+1+4+2+2`. |
| `cargo build -p tomorrowci --release` | PASS | Release binary built. |
| `target/release/tomorrowci.exe --version` | PASS | `tomorrowci 0.1.0`. |
| `target/release/tomorrowci.exe doctor` | BLOCKED_LOCAL | Exit 4. Docker CLI 29.6.2 was present but its daemon was unavailable. The Podman command was missing. Doctor also reported npm missing even though host `npm --version` returned 12.0.2; this is an open diagnostic finding. |
| `npm ci` in `apps/web` | PASS_WITH_FINDINGS | Install completed; npm audit reported 5 vulnerabilities: 3 moderate, 1 high, and 1 critical. |
| `npm test -- --run` in `apps/web` | PASS | Vitest `3/3`. |
| `npm run build` in `apps/web` | PASS | Production build completed. |

At the initial baseline, local live Docker execution was `BLOCKED_LOCAL`, and local Podman execution was `NOT_RUN` because the command was missing. The public CI evidence above closes the Docker fixture observation for that exact GitHub SHA only. A later local branch-candidate run is recorded below; there is still no inspected public Podman fixture run.

### Subsequent local Docker branch-candidate evidence

After Docker Desktop became available on the same Windows host, the six built-in fixtures were run locally with Docker Desktop 29.6.2 using exact commit `aeb51a81d2e1288b9d5f16b5ea4e8ed39c9ff544`. The observed run window was `2026-08-09T12:00:00Z` through `2026-08-09T12:12:57Z`.

- All six fixture expectation contracts completed, and the suite recorded `trustworthy=true`.
- The combined claim count was `PASS=56`, with `FAIL=0`, `BLOCKED=0`, `NOT_RUN=0`, and `SKIP=0`.
- The candidate's `verify` command separately returned PASS for each of the six generated run bundles.
- Evidence was written under a temporary `%TEMP%` directory. It is local, project-owned evidence, not durable public CI evidence and not independent external-adoption evidence.
- This run did not execute the required replay contract and does not close the replay, external, or stable-release gates.

| Run ID | Verified file count | `verify` result |
| --- | ---: | --- |
| `5234ee587e61` | 64 | PASS |
| `5f6f01c0e9e4` | 21 | PASS |
| `83b8bfa7a323` | 52 | PASS |
| `bc8cb37e8bb4` | 42 | PASS |
| `c8d5dd2d8165` | 73 | PASS |
| `f31d689fe013` | 21 | PASS |

## Existing release read-back

Existing release: [`v0.1.0-grok-session`](https://github.com/taipei49314/tomorrowci/releases/tag/v0.1.0-grok-session), published 2026-08-06T05:15:10Z.

- Annotated tag object: [`39011d3bbc30ad943e5e81ef70017fd535942092`](https://api.github.com/repos/taipei49314/tomorrowci/git/tags/39011d3bbc30ad943e5e81ef70017fd535942092)
- Peeled commit: [`7a08c4884761b70e9ae0e63012ee87fdc1e39348`](https://github.com/taipei49314/tomorrowci/commit/7a08c4884761b70e9ae0e63012ee87fdc1e39348)
- Current audited default SHA: `1f42003a561630164699f94f274727be23f2c1a8`

The existing release is historical and does not point at the current audited default SHA. It was not modified.

| Asset | Bytes | Downloaded SHA-256 | Read-back |
| --- | ---: | --- | --- |
| [`tomorrowci-v0.1.0-grok-session-x86_64-unknown-linux-gnu.tar.gz`](https://github.com/taipei49314/tomorrowci/releases/download/v0.1.0-grok-session/tomorrowci-v0.1.0-grok-session-x86_64-unknown-linux-gnu.tar.gz) | 1,004,422 | `08b4fb8632abc7a0d69a54ec8da1b364c598a733145e24e07a6e6617a0abcd24` | Archive checksum matched; extracted CLI reported `0.1.0`. |
| [`tomorrowci-v0.1.0-grok-session-x86_64-pc-windows-msvc.zip`](https://github.com/taipei49314/tomorrowci/releases/download/v0.1.0-grok-session/tomorrowci-v0.1.0-grok-session-x86_64-pc-windows-msvc.zip) | 827,770 | `f2ba4b22dc445a8f452908c3bd6fdee8a96b4fa4f171852054c20401339463dd` | Archive checksum matched; extracted CLI reported `0.1.0`. |
| [`tomorrowci-v0.1.0-grok-session-x86_64-apple-darwin.tar.gz`](https://github.com/taipei49314/tomorrowci/releases/download/v0.1.0-grok-session/tomorrowci-v0.1.0-grok-session-x86_64-apple-darwin.tar.gz) | 905,831 | `f0bce434b183a35e63cd1fe9ea82b65ba83428d66519ff9950d3886c52be299f` | **FAIL:** asset name says `x86_64`, but the extracted Mach-O binary identifies as `arm64`. It was not executable on the Windows audit host. |
| [`SHA256SUMS.txt`](https://github.com/taipei49314/tomorrowci/releases/download/v0.1.0-grok-session/SHA256SUMS.txt) | 383 | `6c2a46a756b7dbda0bc7a634ed3a77fb48bdccabf49f89ac81f202268d2ce040` | Its three archive entries verified, but it omits `sbom.cdx.json`; therefore release inventory coverage is incomplete. |
| [`sbom.cdx.json`](https://github.com/taipei49314/tomorrowci/releases/download/v0.1.0-grok-session/sbom.cdx.json) | 219 | `b6e7d290452775d6374f2c14d2f6a50f408bfb1dd22897fca463481110eaffec` | **FAIL:** parses as CycloneDX 1.5 but has `components=[]`, while the audited `Cargo.lock` contains 105 packages. |

No provenance or artifact-attestation asset appears in the five-asset release inventory. The three archive hashes being internally consistent does not cure the mislabeled macOS architecture, empty SBOM, or incomplete checksum coverage.

## Baseline gate result

- Source formatting, lint, tests, release build, CLI version, web tests, and web build passed locally.
- All six built-in fixture expectations passed on public Docker CI at the exact default SHA.
- The initial local Docker check was blocked; a subsequent local Docker Desktop 29.6.2 run at exact branch commit `aeb51a81d2e1288b9d5f16b5ea4e8ed39c9ff544` passed all six fixture expectations and verified all six generated run bundles. Podman remains missing locally, and no public Podman fixture evidence was inspected.
- End-to-end `scan -> verify -> replay x2 -> verify` is **NOT_RUN** and cannot exist at this baseline because the CLI lacks `verify`; the public measure run performed scans only.
- The existing release has three material qualification failures: mislabeled macOS architecture, an empty dependency SBOM, and incomplete checksum coverage.
- Independent external maintainer/adopter/auditor evidence is **BLOCKED_EXTERNAL** and must not be self-attested.

Accordingly, this baseline is **not qualified for a new tag/release or a 100% claim**. The actionable and blocked gates are recorded in [`BACKLOG.json`](BACKLOG.json).

## Reproduction commands

```text
gh repo view taipei49314/tomorrowci --json url,defaultBranchRef,latestRelease,issues,pullRequests
gh api repos/taipei49314/tomorrowci/commits/master --jq .sha
gh run view 31185394369 --repo taipei49314/tomorrowci
gh run download 31185394369 --repo taipei49314/tomorrowci --name tomorrowci-ci-evidence
gh release view v0.1.0-grok-session --repo taipei49314/tomorrowci
gh release download v0.1.0-grok-session --repo taipei49314/tomorrowci

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p tomorrowci --release
target/release/tomorrowci.exe --version
target/release/tomorrowci.exe doctor

cd apps/web
npm ci
npm test -- --run
npm run build
```
