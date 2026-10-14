import json
from pathlib import Path

from sinkfixtures import make_bundle

from sentry_v2.sinks.spool import Spool


def test_push_pending_ack_in_id_order(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "spool")
    bundles = [make_bundle() for _ in range(3)]
    for b in reversed(bundles):
        spool.push(b)
    pending = list(spool.pending())
    assert [b["id"] for _, b in pending] == [b["id"] for b in bundles]
    assert pending[0][0].name == f"{bundles[0]['id']}.json"
    spool.ack(pending[0][0])
    assert [b["id"] for _, b in spool.pending()] == [b["id"] for b in bundles[1:]]
    assert not list((tmp_path / "spool").glob("*.tmp"))


def test_push_is_idempotent_per_id(tmp_path: Path) -> None:
    spool = Spool(tmp_path)
    b = make_bundle()
    spool.push(b)
    spool.push(b)
    assert len(list(spool.pending())) == 1


def test_cap_by_count_drops_oldest(tmp_path: Path) -> None:
    spool = Spool(tmp_path, max_files=2)
    bundles = [make_bundle() for _ in range(3)]
    for b in bundles:
        spool.push(b)
    assert [b["id"] for _, b in spool.pending()] == [b["id"] for b in bundles[1:]]
    assert spool.dropped == 1


def test_cap_by_size_drops_oldest(tmp_path: Path) -> None:
    one = len(json.dumps(make_bundle(), separators=(",", ":")))
    spool = Spool(tmp_path, max_bytes=one * 2 + 10)
    bundles = [make_bundle() for _ in range(4)]
    for b in bundles:
        spool.push(b)
    assert [b["id"] for _, b in spool.pending()] == [b["id"] for b in bundles[2:]]
    assert spool.dropped == 2


def test_corrupt_file_is_discarded(tmp_path: Path) -> None:
    spool = Spool(tmp_path)
    (tmp_path / "00000000-0000-7000-8000-000000000000.json").write_text("{not json")
    good = make_bundle()
    spool.push(good)
    assert [b["id"] for _, b in spool.pending()] == [good["id"]]
    assert spool.dropped == 1
