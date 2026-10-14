"""Shared pytest fixtures. Integration tests are opt-in via `-m integration`."""

from pathlib import Path

import pytest

PRESSURE = "{k} avg10={a:.2f} avg60=0.20 avg300=0.00 total=12345\n"


@pytest.fixture
def fake_cgroupfs(tmp_path: Path) -> Path:
    """Build a tiny cgroup v2 tree plus /proc/pressure and /proc/<pid>/cgroup."""
    root = tmp_path / "cgroup"
    for rel in (
        "system.slice/batch-1.service",
        "system.slice/batch-2.service",
        "system.slice/nginx.service",
    ):
        d = root / rel
        d.mkdir(parents=True)
        for res in ("memory", "cpu", "io"):
            (d / f"{res}.pressure").write_text(
                PRESSURE.format(k="some", a=42) + PRESSURE.format(k="full", a=0)
            )
        (d / "memory.current").write_text("4096\n")
    proc = tmp_path / "proc"
    (proc / "pressure").mkdir(parents=True)
    (proc / "pressure" / "memory").write_text("some avg10=0.00\n")
    (proc / "77").mkdir()
    (proc / "77" / "cgroup").write_text("0::/system.slice/nginx.service\n")
    return tmp_path
