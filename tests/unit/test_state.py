import dataclasses
import json
import logging
import stat
from pathlib import Path

import pytest

from sentry_v2.state import ActionJournal, ActionRecord

DAY = 86400.0


def record(id: str = "a1", status: str = "applied", **kw: object) -> ActionRecord:
    base = ActionRecord(
        id=id,
        policy="p",
        action="throttle",
        target="batch-1.service",
        mode="enforce",
        status=status,  # type: ignore[arg-type]
        previous={"memory_high": 2**64 - 1},
        applied_at=10.0,
        expires_at=70.0,
        error=None,
        incident_id="i1",
    )
    return dataclasses.replace(base, **kw)  # type: ignore[arg-type]


def test_append_writes_fsynced_json_line_with_ts(tmp_path: Path) -> None:
    j = ActionJournal(tmp_path / "state" / "actions.jsonl", clock=lambda: 123.0)
    j.append(record())
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    line = json.loads((tmp_path / "state" / "actions.jsonl").read_text())
    assert line["ts"] == 123.0
    assert line["previous"] == {"memory_high": 2**64 - 1}


def test_load_last_record_per_id_wins(tmp_path: Path) -> None:
    j = ActionJournal(tmp_path / "actions.jsonl")
    j.append(record(status="planned"))
    j.append(record())
    j.append(record(id="b2", status="dry_run"))
    loaded = j.load()
    assert loaded["a1"] == record()
    assert loaded["b2"].status == "dry_run"


def test_load_missing_file_is_empty(tmp_path: Path) -> None:
    assert ActionJournal(tmp_path / "actions.jsonl").load() == {}


def test_truncated_last_line_ignored_and_repaired(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "actions.jsonl"
    j = ActionJournal(path)
    j.append(record(status="planned"))
    with path.open("a") as f:
        f.write('{"id": "a1", "status": "appl')
    with caplog.at_level(logging.WARNING):
        assert j.load()["a1"].status == "planned"
    assert "truncated" in caplog.text
    # the partial tail is cut so the next append starts on a clean line
    j.append(record())
    assert j.load()["a1"].status == "applied"


def test_corrupt_middle_line_skipped(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "actions.jsonl"
    j = ActionJournal(path)
    j.append(record(id="a1"))
    with path.open("a") as f:
        f.write("not json\n")
    j.append(record(id="b2"))
    assert set(j.load()) == {"a1", "b2"}
    assert "unreadable" in caplog.text


def test_compact_drops_old_closed_keeps_open(tmp_path: Path) -> None:
    now = [0.0]
    path = tmp_path / "actions.jsonl"
    j = ActionJournal(path, clock=lambda: now[0])
    j.append(record(id="old-closed", status="planned"))
    j.append(record(id="old-closed", status="rolled_back"))
    j.append(record(id="old-open", status="applied"))
    j.append(record(id="old-backup", action="backup_reload", expires_at=None))
    now[0] = 6 * DAY
    j.append(record(id="new-closed", status="failed"))
    now[0] = 8 * DAY
    j.compact(older_than=7 * DAY, now=now[0])
    assert set(j.load()) == {"old-open", "new-closed"}
    assert len(path.read_text().splitlines()) == 2


def test_is_open() -> None:
    assert record(status="planned").is_open
    assert record(status="applied").is_open
    assert not record(status="rolled_back").is_open
    assert not record(action="backup_reload", status="applied").is_open
    assert record(action="backup_reload", status="planned").is_open
    assert not record(action="notify", status="applied").is_open
