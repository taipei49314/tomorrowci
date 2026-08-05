"""
Deterministic runtime break:
On Python < 3.10, `collections.MutableMapping` still works (alias, deprecated).
On Python >= 3.10, importing MutableMapping from collections raises ImportError
(must use collections.abc).

This is a real, documented stdlib change — OBSERVED when executed on concrete images.
"""

import sys


def test_mutable_mapping_from_collections():
    # Intentionally use the removed import path.
    from collections import MutableMapping  # noqa: F401

    assert MutableMapping is not None
    assert sys.version_info < (3, 10), "should only pass on Python < 3.10"
