"""A memory hog under MemoryHigh stalls on reclaim; the throttle policy squeezes it, then lets go.

The hog touches 80 MiB in a loop inside MemoryHigh=40M, so the kernel
reclaims from it on every pass and the unit's memory.pressure climbs. The
policy (config/policies.d/10-throttle.toml) sets CPUWeight=10 and
MemoryHigh=48M for 30s.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from conftest import records_for, show, wait_for

pytestmark = pytest.mark.integration

HOG = """
b = bytearray(80 << 20)
while True:
    for i in range(0, len(b), 4096):
        b[i] = (b[i] + 1) & 255
"""


def _status(unit: str, status: str) -> dict[str, object] | None:
    return next((r for r in records_for(unit) if r["status"] == status), None)


def test_throttle_applies_and_rolls_back(transient_unit: Callable[..., str]) -> None:
    unit = transient_unit("throttle", ["python3", "-c", HOG], "MemoryHigh=40M", "MemorySwapMax=64M")
    before = {p: show(unit, p) for p in ("CPUWeight", "MemoryHigh")}

    rec = wait_for(lambda: _status(unit, "applied"), 90, "the throttle to be applied")
    assert rec["action"] == "throttle"
    assert show(unit, "CPUWeight") == "10"
    assert show(unit, "MemoryHigh") == str(48 << 20)

    wait_for(lambda: _status(unit, "rolled_back"), 50, "the throttle to expire")
    assert {p: show(unit, p) for p in before} == before
