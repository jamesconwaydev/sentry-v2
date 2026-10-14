import asyncio
import json
import socket
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentry_v2.collectors import journal
from sentry_v2.collectors.journal import JournalCollector, entry_to_event, unit_tail
from sentry_v2.events import EventQueue, UnitEvent

FIXTURE = Path(__file__).parent.parent / "fixtures" / "journal" / "unit_failure.jsonl"
ENTRIES = [json.loads(line) for line in FIXTURE.read_text().splitlines()]
# fixture order: exited, failed, start_failed, started, app output, exited, failed, start_failed
EXITED, FAILED, START_FAILED, STARTED, APP_OUTPUT = ENTRIES[:5]


class FakeReader:
    def __init__(self, entries=(), history=()):
        self.entries = list(entries)  # new entries for get_next
        self.history = list(history)  # past entries for get_previous
        self.calls: list[tuple] = []
        self.sock, self.peer = socket.socketpair()
        self.closed = False

    def fileno(self):
        return self.sock.fileno()

    def process(self):
        self.calls.append(("process",))

    def get_next(self):
        return self.entries.pop(0) if self.entries else {}

    def get_previous(self):
        return self.history.pop() if self.history else {}

    def seek_tail(self):
        self.calls.append(("seek_tail",))

    def add_match(self, **kw):
        self.calls.append(("add_match", kw))

    def add_disjunction(self):
        self.calls.append(("add_disjunction",))

    def this_boot(self):
        self.calls.append(("this_boot",))

    def close(self):
        self.closed = True
        self.sock.close()
        self.peer.close()


def test_failed_entry():
    assert entry_to_event(FAILED) == UnitEvent(
        ts_us=1792020145050054,
        unit="demo-reset.service",
        kind="failed",
        result="exit-code",
        invocation_id="8379e0461015401e86620638b7b937e3",
    )


def test_exited_entry_carries_exit_status():
    ev = entry_to_event(EXITED)
    assert ev is not None
    assert (ev.kind, ev.exit_code, ev.exit_status) == ("exited", "exited", "1")


def test_start_failed_entry():
    ev = entry_to_event(START_FAILED)
    assert ev is not None
    assert (ev.kind, ev.result, ev.main_pid) == ("start_failed", "failed", None)


def test_unrelated_entries_yield_nothing():
    assert entry_to_event(STARTED) is None
    assert entry_to_event(APP_OUTPUT) is None
    assert entry_to_event({}) is None


def test_accepts_python_systemd_types():
    entry = dict(FAILED)
    entry["__REALTIME_TIMESTAMP"] = datetime(2026, 10, 14, 12, 0, 0, 123456, tzinfo=UTC)
    entry["MESSAGE_ID"] = uuid.UUID(FAILED["MESSAGE_ID"])
    entry["_PID"] = 1
    ev = entry_to_event(entry)
    assert ev is not None and ev.kind == "failed"
    assert ev.ts_us == 1791979200_123456


def test_naive_datetime_and_int_timestamp():
    entry = dict(FAILED, __REALTIME_TIMESTAMP=datetime(2026, 10, 14, 12, 0, 0, 5))
    ev = entry_to_event(entry)
    assert ev is not None and ev.ts_us % 1_000_000 == 5
    assert entry_to_event(dict(FAILED, __REALTIME_TIMESTAMP=42)).ts_us == 42  # type: ignore[union-attr]


def test_ignores_user_manager_and_spoofed_entries():
    user = {k: v for k, v in FAILED.items() if k != "UNIT"} | {"USER_UNIT": "x.service"}
    assert entry_to_event(user) is None
    assert entry_to_event(dict(FAILED, _PID="4242")) is None
    assert entry_to_event({k: v for k, v in FAILED.items() if k != "_PID"}) is None


def test_missing_timestamp_is_skipped():
    assert entry_to_event({k: v for k, v in FAILED.items() if k != "__REALTIME_TIMESTAMP"}) is None


def test_unit_tail_returns_last_n_oldest_first():
    entries = [
        {"__REALTIME_TIMESTAMP": datetime(2026, 1, 1, tzinfo=UTC), "PRIORITY": 3, "MESSAGE": "a"},
        {"__REALTIME_TIMESTAMP": "2000000", "PRIORITY": "4", "MESSAGE": "b"},
        {"__REALTIME_TIMESTAMP": 3000000, "MESSAGE": b"c"},
    ]
    reader = FakeReader(history=entries)
    out = unit_tail("demo-reset.service", 2, lambda: reader)
    assert out == [
        {"ts_us": 2000000, "priority": 4, "message": "b"},
        {"ts_us": 3000000, "priority": 6, "message": "c"},
    ]
    assert reader.calls == [
        ("add_match", {"_SYSTEMD_UNIT": "demo-reset.service"}),
        ("add_disjunction",),
        ("add_match", {"UNIT": "demo-reset.service", "_PID": "1"}),
        ("this_boot",),
        ("seek_tail",),
    ]
    assert reader.closed


def test_unit_tail_short_journal():
    reader = FakeReader(history=[{"__REALTIME_TIMESTAMP": "1", "MESSAGE": "only"}])
    assert len(unit_tail("x.service", 10, lambda: reader)) == 1


def make(entries, hints, now=lambda: 0.0):
    reader = FakeReader(entries)
    q = EventQueue()
    c = JournalCollector(q, lambda: reader, lambda: hints.append(1), monotonic=now)
    return c, reader, q


def test_open_applies_standard_setup():
    c, reader, _ = make([], [])
    c._open()
    assert reader.calls == [
        ("this_boot",),
        ("add_match", {"_PID": "1"}),
        ("seek_tail",),
    ]


def test_drain_queues_events_and_hints_once():
    async def go():
        hints: list[int] = []
        c, _, q = make([FAILED, STARTED, STARTED, APP_OUTPUT, START_FAILED], hints)
        c._reader = c._open()
        c._drain()
        assert len(q) == 2
        assert hints == [1]  # second STARTED is inside the debounce window
        await asyncio.sleep(1.1)  # trailing hint fires
        assert hints == [1, 1]
        c.close()

    asyncio.run(go())


def test_drain_is_capped_and_resumes():
    async def go():
        entries = [dict(FAILED) for _ in range(journal.MAX_PER_WAKEUP + 5)]
        c, _, q = make(entries, [])
        c._reader = c._open()
        c._drain()
        assert len(q) == journal.MAX_PER_WAKEUP
        await asyncio.sleep(0)
        assert len(q) == journal.MAX_PER_WAKEUP + 5
        c.close()

    asyncio.run(go())


def test_run_wakes_on_fd_and_cleans_up():
    async def go():
        c, reader, q = make([], [])
        task = asyncio.create_task(c.run())
        await asyncio.sleep(0.05)
        assert c.health() == {"state": "ok"}
        reader.entries.append(FAILED)
        reader.peer.send(b"x")
        ev = await asyncio.wait_for(q.get(), 2)
        assert isinstance(ev, UnitEvent) and ev.unit == "demo-reset.service"
        assert ("process",) in reader.calls
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert reader.closed

    asyncio.run(go())


def test_run_reports_open_failure():
    def boom():
        raise RuntimeError("no journal")

    c = JournalCollector(EventQueue(), boom, lambda: None)
    asyncio.run(c.run())
    assert c.health()["state"] == "error"


def test_on_readable_survives_reader_errors():
    async def go():
        c, reader, _ = make([], [])
        c._reader = c._open()

        def bad():
            raise OSError("gone")

        reader.process = bad  # type: ignore[method-assign]
        c._on_readable()  # logged, not raised
        c.close()

    asyncio.run(go())


def test_real_reader_api_has_not_drifted():
    pytest.importorskip("systemd.journal")
    reader = journal.open_reader()
    try:
        assert isinstance(reader.fileno(), int)
    finally:
        reader.close()  # type: ignore[attr-defined]
