"""Dependency-axis fixture: vendor package old API must remain available."""

import sys
from pathlib import Path


def test_legacy_api_present():
    vendor = Path(__file__).resolve().parents[1] / "vendor"
    sys.path.insert(0, str(vendor))
    import legacycompat

    assert hasattr(legacycompat, "old_function")
    assert legacycompat.old_function() == 42
    if getattr(legacycompat, "BREAKING_VERSION", 1) >= 2:
        raise AssertionError("legacycompat 2.x removed old_function contract")
