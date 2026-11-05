"""Run Mistune v3.0.2's two original full-suite commands unchanged in scope."""
import subprocess
import sys
for label, arguments in [("original-full-suite", []), ("original-coverage", ["--cov=mistune", "--cov-report=xml"])]:
    print("REHEARSAL_STAGE=" + label, flush=True)
    result = subprocess.run([sys.executable, "-m", "pytest", *arguments])
    print("REHEARSAL_STAGE_EXIT=" + label + ":" + str(result.returncode), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
