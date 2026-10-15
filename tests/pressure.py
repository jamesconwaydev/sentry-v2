"""Text of a cgroup *.pressure file, shared by fixtures and tests."""

_LINE = "{k} avg10={a:.2f} avg60=0.20 avg300=0.00 total=12345\n"


def pressure_text(some: float, full: float = 0.0) -> str:
    """A two-line pressure file with the given avg10 values."""
    return _LINE.format(k="some", a=some) + _LINE.format(k="full", a=full)
