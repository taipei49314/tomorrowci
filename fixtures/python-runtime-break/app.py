"""Breaks on Python 3.10+: collections.MutableMapping was removed."""

# This import works on 3.9 and fails on 3.10+ with ImportError.
from collections import MutableMapping  # noqa: F401


def ok():
    return True
