"""
Deterministic runtime break:
On Python < 3.10, `collections.MutableMapping` still works (alias, deprecated).
On Python >= 3.10, importing MutableMapping from collections raises ImportError
(must use collections.abc).

This is a real, documented stdlib change — OBSERVED when executed on concrete images.
"""

import sys
import unittest


class CollectionsCompatibilityTest(unittest.TestCase):
    def test_mutable_mapping_from_collections(self):
        # Intentionally use the removed import path.
        from collections import MutableMapping

        self.assertIsNotNone(MutableMapping)
        self.assertLess(
            sys.version_info,
            (3, 10),
            "should only pass on Python < 3.10",
        )
