"""Alternates pass/fail using a counter file in the mounted workspace."""

from pathlib import Path


def test_flaky():
    # Must live on the mounted workspace so reruns in new containers see state.
    # /tmp is container-local and resets every attempt → would look like hard FAIL.
    p = Path("/workspace/.tomorrowci-flaky-counter")
    n = 0
    if p.exists():
        n = int(p.read_text().strip() or "0")
    p.write_text(str(n + 1))
    # Odd attempts fail, even pass → inconsistent across reruns → FLAKY
    assert n % 2 == 1, f"flaky fail on count {n}"
