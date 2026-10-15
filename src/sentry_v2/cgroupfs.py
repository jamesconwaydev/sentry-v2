"""Thin, testable access to the cgroup v2 filesystem and /proc."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from .events import PressureLine
from .policy import target_matches

UNIT_SUFFIXES = (".service", ".scope", ".slice")


def parse_pressure(text: str) -> dict[str, PressureLine]:
    """Parse a *.pressure file into {"some": ..., "full": ...}."""
    out: dict[str, PressureLine] = {}
    for line in text.splitlines():
        kind, *fields = line.split()
        kv = dict(f.split("=", 1) for f in fields)
        out[kind] = PressureLine(
            float(kv["avg10"]), float(kv["avg60"]), float(kv["avg300"]), int(kv["total"])
        )
    return out


class CgroupFS:
    def __init__(self, root: Path = Path("/sys/fs/cgroup"), proc: Path = Path("/proc")) -> None:
        self.root = root
        self.proc = proc

    def psi_available(self) -> bool:
        return os.access(self.proc / "pressure" / "memory", os.R_OK)

    def glob(self, patterns: Iterable[str]) -> list[str]:
        """Cgroup directories (relative paths) matching any pattern."""
        pats = tuple(patterns)
        found: list[str] = []
        # ponytail: walks the whole cgroup tree; ceiling is a few thousand
        # cgroups per resolve. Upgrade: prune by each pattern's literal prefix.
        for dirpath, _dirs, _files in os.walk(self.root):
            rel = Path(dirpath).relative_to(self.root).as_posix()
            if rel != "." and any(target_matches(p, rel) for p in pats):
                found.append(rel)
        return sorted(found)

    def read_pressure(self, rel: str, resource: str) -> dict[str, PressureLine]:
        return parse_pressure((self.root / rel / f"{resource}.pressure").read_text())

    def read_system_pressure(self, resource: str) -> dict[str, PressureLine]:
        """System-wide pressure from /proc/pressure, for the root cgroup."""
        return parse_pressure((self.proc / "pressure" / resource).read_text())

    def memory_current(self, rel: str) -> int:
        return int((self.root / rel / "memory.current").read_text())

    def pid_cgroup(self, pid: int) -> str | None:
        try:
            text = (self.proc / str(pid) / "cgroup").read_text()
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("0::"):
                return line[3:].strip("/")
        return None

    def unit_of(self, rel: str) -> str | None:
        last = rel.rsplit("/", 1)[-1]
        return last if last.endswith(UNIT_SUFFIXES) else None

    def open_trigger(
        self, rel: str, resource: str, kind: str, stall_us: int, window_us: int
    ) -> int:
        """Register a PSI trigger; the returned fd raises EPOLLPRI when it fires."""
        fd = os.open(self.root / rel / f"{resource}.pressure", os.O_RDWR | os.O_NONBLOCK)
        try:
            os.write(fd, f"{kind} {stall_us} {window_us}\0".encode())
        except OSError:
            os.close(fd)
            raise
        return fd
