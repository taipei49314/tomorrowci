# Mistune historical Python upgrade rehearsal

Agent-operated engineering case, not human effort or independent adoption data.
This case uses Mistune v3.0.2 at
`f997c86335d8a5d8435aac08b66ed3cba9381b51`, comparing Python 3.11 and 3.14.
Current Mistune already supports newer Python versions; this is not a claim
about its current CI or a newly discovered upstream defect.

Keep both original test commands and the original test/warning configuration:

```sh
python -m pytest
python -m pytest --cov=mistune --cov-report=xml
```

The original job's Codecov upload and other platform/runtime legs are outside
this two-version Linux rehearsal. No source assertion or selection is changed.
`ci_upgrade_tests.py` sequences these commands for TomorrowCI's single command
entry point, stopping on first failure as the original CI did. The matrix uses
the same Python module entry points directly in two native steps.

`requirements.txt` is a new, common wheel-hashed test dependency snapshot,
resolved on 2026-11-05 for Linux x86_64 CPython 3.11/3.14. The historical repo
did not have that lock. It is shared preparation, not a cost charged only to
matrix users. Both arms add those same requirements and wrapper bytes; the
resulting Git tree is `10bf899d05ddded8583c9d70b786acf12793bc69`.

TomorrowCI source is `270545d93ebc10c9bac288af0802c2498ec32f9a`, with the
default venv installer and the explicit configuration here. The container
images were already cached on PJU; the CLI was built freshly from that source
using an existing Rust toolchain/registry. Matrix runs on GitHub's hosted Ubuntu
runner using ordinary setup-python, pip cache and native job rerun.

Machine timing across those hosts is descriptive, not an efficiency benchmark.
No human active time is measured. Check both raw pytest summaries for counts;
neither a successful process nor TomorrowCI's summary alone establishes scope.
These input files contain no experiment outcome; results are recorded separately.
