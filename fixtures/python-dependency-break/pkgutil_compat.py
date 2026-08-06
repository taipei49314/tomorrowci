"""Uses pytest version marker for simulated API — actual break via conftest on latest."""

def version_gate():
    import pytest
    # 7.0.x has __version__; always true for baseline
    return hasattr(pytest, "__version__")
