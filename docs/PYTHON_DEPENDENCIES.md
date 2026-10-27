# Importing real Python dependency updates

`scripts/import_python_dependencies.py` turns two exact pin snapshots into a
wheel-backed `.tomorrowci-dependencies.json` v2 experiment. It preserves unchanged
packages and computes actual updates from wheel identities. It does not contain an
expected culprit, expected verdict or fixture oracle.

The importer prepares input for a scan. A successful import does not establish
that either dependency set installs, that project tests pass, or that a failure is
minimal. Those claims require the recorded scan and replay executions.

## Inputs and scope

- Use a disposable target checkout with the project's existing tests and a
  `.tomorrowci.yml` that supplies the test command and the same Python runtime.
- Supply complete before/after pin snapshots: one `distribution==version` per
  line, including unchanged transitive dependencies and test dependencies.
  Distribution names are normalized; version strings must match wheel metadata.
- Both snapshots must have the same distribution names. There must be 1–64
  actual updates. Additions, removals and same-version artifact replacements are
  rejected. Unchanged dependencies are retained and are not counted as updates.
- Extras, environment markers in the input pins, ranges, editable installs,
  direct URLs, recursive includes and arbitrary pip options are unsupported.
  Markers and version constraints in wheel `Requires-Dist` remain intact for pip
  to evaluate when installing each probe in the target runtime. Direct-reference
  `Requires-Dist` entries containing `@`, including HTTP and `file:` URLs, are
  rejected: they could introduce an artifact outside the selected snapshot even
  when pip's index lookup is disabled.
- Plain exact pins are accepted. Optional `--hash=sha256:<64 lowercase hex>`
  entries bind the input to known wheel bytes; multiple hashes and continued
  lines are supported. If any pin in a snapshot has hashes, every pin in that
  snapshot must have hashes. `--require-hashes` requires both complete hash locks.
  Without input hashes, the import records the bytes selected at download time;
  it does not establish that a mutable registry previously served the same bytes.
- Only wheels are imported. No sdist is extracted or built and no wheel module
  is imported. Keep an sdist/build receipt separately if a wheel was built before
  import; this importer makes no assertion about that build's provenance.

## Download and import

Load the intended immutable Python container image locally first. The image must
contain Python and pip, and its Python major/minor must match `--runtime`.

```powershell
python scripts/import_python_dependencies.py `
  --target C:/work/disposable-project `
  --before C:/work/requirements.before.txt `
  --after C:/work/requirements.after.txt `
  --runtime 3.11 `
  --image python@sha256:<actual-image-digest> `
  --output-dir vendor/python-dependencies
```

The two downloads run separately in that pinned image using
`pip download --only-binary=:all: --no-deps` against public PyPI. This selects
target-platform wheels without running source builds or resolving additional
unlisted dependencies. The download containers have a read-only root, numeric
unprivileged user, dropped capabilities, no-new-privileges, memory/CPU/PID limits,
a bounded temporary filesystem and a per-snapshot wall timeout. Only generated
pin inputs are mounted read-only, with a task-local output directory writable;
the checkout, host Docker socket, host credentials and environment are not mounted
or forwarded. Downloads use bridge networking. Scan test phases are separate and
must run with network disabled.

The script checks wheel identity, bounded ZIP metadata, duplicate/unsafe archive
paths, and input hashes before publication. It reads archives without extracting
them. Resource bounds are 256 distributions, 128 MiB per wheel, 512 MiB across
the combined artifact snapshot, 10,000 ZIP members per wheel, 512 MiB declared
uncompressed wheel data, and 1 MiB per metadata file.

## Offline artifacts

Add `--wheelhouse C:/work/selected-wheels` to skip Docker and network access.
The directory must be flat, with exactly one matching artifact for each selected
name/version. Other versions may coexist. Multiple matching platform/build
wheels are rejected rather than selected using the host's platform.

Offline mode does not assert platform compatibility. The later probe installation
in the pinned runtime checks compatibility. A missing wheel, unsupported tag,
missing transitive dependency or incompatible version constraint must block that
probe before project tests. The scan materializer must install the complete
selected set with dependency checking enabled, `--no-index`, and no access to
unselected artifacts; using `--no-deps` during probe installation would invalidate
that closure check. The download-only use of `--no-deps` has a different purpose:
it prevents silently expanding the supplied full pin snapshots.

## Outputs and evidence

The output directory must be new, relative to the checkout, and outside `.git`
and `.tomorrowci`. The importer refuses an existing dependency manifest, output
directory, or concurrent import lock. Artifacts are staged and validated first;
the root manifest is published last using an atomic, exclusive hard link. NTFS
and ext4 support this operation. If publication fails after the new artifact
directory is reserved, that directory is retained for inspection, and existing
user files are not overwritten. Choose a fresh output path after investigating
such a failure.

The output contains original wheel bytes under a flat `wheels/<original-filename>` directory,
the original pin snapshots, sanitized download logs, and `provenance.json`.
Provenance binds the importer source, input hashes, runtime image, selected wheel
hashes, metadata, generated manifest hash and import mode. A source URL is saved
only when it appears unambiguously in the download log; credentials, query strings
and fragments are removed. Missing URLs are recorded as null. Hashes bind the
selected bytes; a URL alone is not an integrity guarantee.
Flat wheel paths avoid adding a 64-character directory to long native-wheel
filenames on Windows. Full SHA256 identities remain in the manifest and provenance;
conflicting bytes with the same filename are rejected.

The v2 manifest uses `content_hash_algorithm: sha256-file-v1`, with changed
packages in `candidate.changes` and fixed packages in `unchanged`. Each artifact
contains `version`, workspace-relative `source`, and `content_sha256`.
The scanner must validate these bytes again before installation and replay.

## Scan configuration and replay

For a Python 3.11 project whose supplied test dependencies include pytest, save
this as `.tomorrowci.yml` in the target checkout. Replace the test command with
the project's real command if it uses a different test runner; that runner and
its dependency closure must be present in both pin snapshots.

```yaml
version: 1
project:
  ecosystem: python
  test_command: python -m pytest -q
baseline:
  runtime: "3.11"
  dependencies: locked
candidates:
  runtime:
    versions: []
    max_versions: 0
  dependencies:
    latest_allowed: false
    prerelease: false
execution:
  max_scenarios: 24
  reruns_on_failure: 3
  timeout_seconds: 300
  max_parallel: 1
sandbox:
  engine: docker
  network: fetch-only
  memory_mb: 2048
  cpus: 1
  pids_limit: 256
```

The manifest and configuration must pin the same runtime. V2 dependency
experiments use one immutable runtime image; simultaneous runtime candidates are
rejected. The empty `versions` list and zero `max_versions` make that intent
explicit. The three failure attempts are required for dependency reduction.

`network: fetch-only` is the configuration schema's sandbox policy name. The v2
wheel execution contract is stricter: **both installation and tests run with
network `none`**, including replay. Before installation, a container-side guard
checks each wheel's declared name/version against METADATA and rejects direct
dependency references. Pip checks version constraints across the complete
selected artifact set offline. A second guard checks that installed distribution
names and versions exactly equal the selected set before tests can start.

Run the commands from the imported target checkout. Keep the run ID returned by
this scan; do not choose a different run by directory modification time. For a
failure, use the scenario ID from the scan's displayed reproduction command
(which can identify a reduced subset).

```powershell
Set-Location C:/work/disposable-project
tomorrowci scan . --config .tomorrowci.yml
# Set these to the IDs printed by this scan.
$runId = '<returned-run-id>'
$scenarioId = '<returned-replay-scenario-id>'
tomorrowci verify $runId
tomorrowci replay $runId --scenario $scenarioId
tomorrowci replay $runId --scenario $scenarioId
tomorrowci verify $runId
```

A useful
dependency-break trial needs a passing baseline, a stable candidate failure,
actually executed reduction probes, an independently verified necessary subset,
and repeated replay of the same failure. Invalid hybrid dependency combinations
are blocked installations, not proof that the removed update was necessary.
The adaptive search's execution budget still limits what it can establish; 64
accepted updates do not promise that every subset will be tested.

Importer unit tests run without Docker, package execution or registry access:

```powershell
python scripts/test_import_python_dependencies.py
```
