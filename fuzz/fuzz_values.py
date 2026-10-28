"""Coverage-guided fuzzing of the parsers for PSI files and config values."""

import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from sentry_v2.cgroupfs import parse_pressure
    from sentry_v2.units import parse_duration, parse_size


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    # These are the errors their callers catch; anything else is a bug.
    with contextlib.suppress(ValueError, KeyError):
        parse_pressure(fdp.ConsumeUnicodeNoSurrogates(512))
    value = fdp.ConsumeUnicodeNoSurrogates(32)
    for parse in (parse_duration, parse_size):
        with contextlib.suppress(ValueError):
            parse(value)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
