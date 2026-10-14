"""Parsers for the duration and size strings used in configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)(us|ms|s|m|h|d)$")
_DURATION_SCALE = {"us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
_SIZE = re.compile(r"^(\d+)([KMGT]?)$")
_SIZE_SCALE = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_PERCENT = re.compile(r"^(\d+(?:\.\d+)?)%$")


@dataclass(frozen=True)
class Percent:
    """A percentage of some base amount, resolved at decision time."""

    value: float

    def of(self, n: int) -> int:
        return int(n * self.value / 100)


def parse_duration(s: str) -> float:
    """Return seconds for strings like ``150ms``, ``10s``, ``5m``, ``1h``, ``30d``."""
    m = _DURATION.match(s)
    if m is None:
        raise ValueError(
            f"invalid duration {s!r}: expected a number and one unit of us, ms, s, m, h, d"
        )
    return float(m.group(1)) * _DURATION_SCALE[m.group(2)]


def parse_size(s: str) -> int | Percent:
    """Return bytes for ``512M`` (binary units K, M, G, T) or a Percent for ``90%``."""
    m = _PERCENT.match(s)
    if m is not None:
        pct = float(m.group(1))
        if not 0 < pct <= 100:
            raise ValueError(f"invalid size {s!r}: percentage must be above 0 and at most 100")
        return Percent(pct)
    m = _SIZE.match(s)
    if m is None:
        raise ValueError(
            f"invalid size {s!r}: expected digits with optional K, M, G, T or a percentage"
        )
    return int(m.group(1)) * _SIZE_SCALE[m.group(2)]
