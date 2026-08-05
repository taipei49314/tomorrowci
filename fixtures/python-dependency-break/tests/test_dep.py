"""Dependency-axis fixture: vendor API must remain v1 under locked deps."""

import os
import sys
from pathlib import Path


def test_legacy_api_present():
    # PYTHONPATH is set by TomorrowCI adapter:
    # locked -> /workspace/vendor (BREAKING_VERSION=1)
    # latest_allowed -> /workspace/vendor/legacycompat_v2 first (BREAKING_VERSION=2)
    import legacycompat

    mode = os.environ.get("TOMORROWCI_DEP_MODE", "locked")
    version = getattr(legacycompat, "BREAKING_VERSION", 1)

    if mode == "locked":
        assert hasattr(legacycompat, "old_function"), "locked mode must keep old_function"
        assert legacycompat.old_function() == 42
        assert version < 2
    else:
        # Simulated upgraded dependency removes old_function contract
        if version >= 2 or not hasattr(legacycompat, "old_function"):
            raise AssertionError(
                "legacycompat 2.x removed old_function contract "
                f"(mode={mode}, version={version}, path={getattr(legacycompat, '__file__', '?')})"
            )
        # If v2 not on path for some reason, still fail when mode says latest
        raise AssertionError(f"expected simulated dep break under mode={mode}")
