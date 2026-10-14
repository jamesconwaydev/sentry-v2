import asyncio
import json
import os
from pathlib import Path

import pytest
from sinkfixtures import FakeTime, make_bundle

from sentry_v2.sinks.file import FileSink


def _files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.json"))


def test_writes_dated_path(tmp_path: Path) -> None:
    sink = FileSink(tmp_path, max_age=3600, max_size=10**9)
    b = make_bundle(ts="2026-10-14T23:59:59+02:00")
    asyncio.run(sink.send(b))
    path = tmp_path / "2026" / "10" / "14" / f"{b['id']}.json"
    assert json.loads(path.read_text()) == b
    assert path.stat().st_mode & 0o777 == 0o600


def test_rejects_id_that_is_not_a_uuid(tmp_path: Path) -> None:
    sink = FileSink(tmp_path, max_age=3600, max_size=10**9)
    with pytest.raises(ValueError):
        asyncio.run(sink.send(make_bundle(id="../../etc/passwd")))


def test_retention_deletes_oldest_beyond_max_size(tmp_path: Path) -> None:
    t = FakeTime()
    t.now = 1e9
    one = len(json.dumps(make_bundle(), separators=(",", ":")))
    sink = FileSink(tmp_path, max_age=10**9, max_size=one * 2 + 10, clock=t.clock)
    bundles = [make_bundle(ts=f"2026-10-{d:02d}T00:00:00Z") for d in (11, 12, 13)]

    async def run() -> None:
        for b in bundles:
            await sink.send(b)
            t.now += 61

    asyncio.run(run())
    assert [p.stem for p in _files(tmp_path)] == [b["id"] for b in bundles[1:]]
    assert not (tmp_path / "2026" / "10" / "11").exists()


def test_retention_deletes_by_age(tmp_path: Path) -> None:
    t = FakeTime()
    t.now = 1e9
    sink = FileSink(tmp_path, max_age=100, max_size=10**9, clock=t.clock)
    old, new = make_bundle(), make_bundle()
    asyncio.run(sink.send(old))
    os.utime(_files(tmp_path)[0], (t.now - 500, t.now - 500))
    t.now += 61
    asyncio.run(sink.send(new))
    assert [p.stem for p in _files(tmp_path)] == [new["id"]]


def test_prunes_at_most_once_a_minute(tmp_path: Path) -> None:
    t = FakeTime()
    t.now = 1e9
    sink = FileSink(tmp_path, max_age=10**9, max_size=1, clock=t.clock)
    asyncio.run(sink.send(make_bundle()))  # first write prunes: dir now empty
    asyncio.run(sink.send(make_bundle()))  # within 60 s: kept
    assert len(_files(tmp_path)) == 1
