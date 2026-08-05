"""Alternates pass/fail using a counter file in /tmp (container-local)."""

from pathlib import Path


def test_flaky():
    p = Path("/tmp/tomorrowci-flaky-counter")
    n = 0
    if p.exists():
        n = int(p.read_text().strip() or "0")
    p.write_text(str(n + 1))
    # Odd attempts fail, even pass → inconsistent across reruns
    assert n % 2 == 1, f"flaky fail on count {n}"
