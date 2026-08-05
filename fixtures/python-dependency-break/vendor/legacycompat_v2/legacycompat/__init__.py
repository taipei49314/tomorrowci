"""Simulated upgraded dependency that breaks the old API contract."""

BREAKING_VERSION = 2


def new_function() -> int:
    return 99
