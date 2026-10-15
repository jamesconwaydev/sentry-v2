"""Shared pytest fixtures. Integration tests are opt-in via `-m integration`."""

from pathlib import Path

import pytest

from pressure import pressure_text


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
            (d / f"{res}.pressure").write_text(pressure_text(42))
        (d / "memory.current").write_text("4096\n")
    proc = tmp_path / "proc"
    (proc / "pressure").mkdir(parents=True)
    (proc / "pressure" / "memory").write_text("some avg10=0.00\n")
    (proc / "77").mkdir()
    (proc / "77" / "cgroup").write_text("0::/system.slice/nginx.service\n")
    return tmp_path
