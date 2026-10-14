"""On-disk queue of undelivered bundles, one JSON file per bundle."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

from .base import Bundle, bundle_filename, encode

log = logging.getLogger(__name__)


def write_atomic(path: Path, data: bytes) -> None:
    """Write via a temp file, fsync it, rename over `path`, then fsync the directory."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class Spool:
    """`<id>.json` files; UUIDv7 ids make filename order delivery order.

    Capped at `max_files` and `max_bytes`; past either, the oldest files go
    and `dropped` counts them.
    """

    def __init__(self, dir: Path, max_files: int = 10000, max_bytes: int = 512 * 1024**2) -> None:
        self.dir = dir
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.dropped = 0
        dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _files(self) -> list[Path]:
        return sorted(self.dir.glob("*.json"))

    def push(self, bundle: Bundle) -> None:
        write_atomic(self.dir / bundle_filename(bundle), encode(bundle))
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        sized = []
        for p in self._files():
            try:
                sized.append((p, p.stat().st_size))
            except FileNotFoundError:  # acked meanwhile
                continue
        total = sum(size for _, size in sized)
        for p, size in sized:
            if len(sized) <= self.max_files and total <= self.max_bytes:
                break
            p.unlink(missing_ok=True)
            sized = sized[1:]
            total -= size
            self.dropped += 1
            log.warning("spool %s full: dropped oldest bundle %s", self.dir, p.stem)

    def pending(self) -> Iterator[tuple[Path, Bundle]]:
        for p in self._files():
            try:
                yield p, json.loads(p.read_bytes())
            except FileNotFoundError:
                continue
            except ValueError:
                log.warning("spool %s: discarding unreadable %s", self.dir, p.name)
                p.unlink(missing_ok=True)
                self.dropped += 1

    def ack(self, path: Path) -> None:
        path.unlink(missing_ok=True)
