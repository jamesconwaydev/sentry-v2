"""Always-on sink: one JSON file per bundle under <root>/YYYY/MM/DD/."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
from collections.abc import Callable
from pathlib import Path

from .base import Bundle, bundle_filename, encode
from .spool import write_atomic

log = logging.getLogger(__name__)

PRUNE_INTERVAL = 60.0


class FileSink:
    name = "file"

    def __init__(
        self,
        root: Path,
        max_age: float,
        max_size: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.root = root
        self.max_age = max_age
        self.max_size = max_size
        self._clock = clock
        self._last_prune: float | None = None

    async def send(self, bundle: Bundle) -> None:
        await asyncio.to_thread(self._write, bundle)

    def _write(self, bundle: Bundle) -> None:
        name = bundle_filename(bundle)
        day = dt.datetime.fromisoformat(bundle["ts"]).astimezone(dt.UTC)
        d = self.root / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"
        d.mkdir(parents=True, exist_ok=True, mode=0o750)
        path = d / name
        write_atomic(path, encode(bundle))  # mkstemp: mode 0600
        now = self._clock()
        if self._last_prune is None or now - self._last_prune >= PRUNE_INTERVAL:
            self._last_prune = now
            self._prune(now)

    def _prune(self, now: float) -> None:
        """Delete bundles older than max_age, then the oldest until under max_size."""
        files = []
        for p in sorted(self.root.glob("*/*/*/*.json")):  # date path then UUIDv7: oldest first
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            if now - st.st_mtime > self.max_age:
                self._remove(p)
            else:
                files.append((p, st.st_size))
        total = sum(size for _, size in files)
        for p, size in files:
            if total <= self.max_size:
                break
            self._remove(p)
            total -= size

    def _remove(self, path: Path) -> None:
        path.unlink(missing_ok=True)
        log.debug("retention: removed %s", path)
        for d in (path.parent, path.parent.parent, path.parent.parent.parent):
            try:
                d.rmdir()
            except OSError:  # not empty
                break
