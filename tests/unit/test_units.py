import re

import pytest

from sentry_v2.units import Percent, parse_duration, parse_size


@pytest.mark.parametrize(
    ("s", "expected"),
    [
        ("150ms", 0.15),
        ("10s", 10.0),
        ("5m", 300.0),
        ("1h", 3600.0),
        ("250us", 0.00025),
        ("30d", 2592000.0),
        ("1.5s", 1.5),
    ],
)
def test_parse_duration(s: str, expected: float) -> None:
    assert parse_duration(s) == pytest.approx(expected)


@pytest.mark.parametrize("bad", ["", "10", "-5s", "1m30s", "5 minutes", "1e3s"])
def test_parse_duration_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match=re.escape(repr(bad))):
        parse_duration(bad)


def test_parse_size() -> None:
    assert parse_size("512M") == 512 * 1024**2
    assert parse_size("1G") == 1024**3
    assert parse_size("4096") == 4096
    assert parse_size("90%") == Percent(90.0)
    assert parse_size("100%") == Percent(100.0)


@pytest.mark.parametrize("bad", ["0%", "101%", "12X", "M", ""])
def test_parse_size_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match=re.escape(repr(bad))):
        parse_size(bad)


def test_percent_of() -> None:
    assert Percent(50.0).of(1000) == 500
