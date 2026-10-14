"""Journal collector: unit failures reported by systemd (PID 1), as UnitEvents."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Protocol

from ..events import EventQueue, UnitEvent

log = logging.getLogger(__name__)

MSG_UNIT_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"  # UNIT_RESULT
MSG_PROCESS_EXITED = "98e322203f7a4ed290d09fe03c09fe15"  # EXIT_CODE, EXIT_STATUS
MSG_START_FAILED = "be02cf6855d2428ba40df7e9d022f03d"  # JOB_RESULT

MAX_PER_WAKEUP = 500
HINT_INTERVAL = 1.0


class ReaderLike(Protocol):
    def fileno(self) -> int: ...
    def process(self) -> object: ...
    def get_next(self) -> dict[str, Any]: ...
    def get_previous(self) -> dict[str, Any]: ...
    def seek_tail(self) -> object: ...
    def add_match(self, **kw: str) -> object: ...
    def add_disjunction(self) -> object: ...
    def this_boot(self) -> object: ...
    def close(self) -> object: ...


def open_reader() -> ReaderLike:
    """A system-journal reader. Imported here so the package loads without systemd."""
    from systemd import journal

    return journal.Reader(flags=journal.SYSTEM_ONLY)  # type: ignore[no-any-return]


def _ts_us(value: object) -> int | None:
    if isinstance(value, datetime):
        return int(value.timestamp()) * 1_000_000 + value.microsecond
    try:
        return int(value)  # type: ignore[call-overload,no-any-return]
    except (TypeError, ValueError):
        return None


def _message_id(value: object) -> str:
    return value.hex if isinstance(value, uuid.UUID) else str(value or "").replace("-", "").lower()


def _text(value: object) -> str:
    if isinstance(value, bytes):  # python-systemd leaves non-UTF-8 fields as bytes
        return value.decode(errors="replace")
    return str(value)


def _from_systemd(entry: Mapping[str, object]) -> bool:
    return str(entry.get("_PID")) == "1" and bool(entry.get("UNIT"))


def _str(entry: Mapping[str, object], key: str) -> str | None:
    value = entry.get(key)
    return None if value is None else str(value)


def entry_to_event(entry: Mapping[str, object]) -> UnitEvent | None:
    """Map a journal entry to a UnitEvent, or None if it is not a unit failure.

    Only entries from systemd itself (PID 1) count: UNIT= is not a trusted
    field, so any process could otherwise forge a failure. User managers log
    USER_UNIT instead and are ignored.
    """
    if not _from_systemd(entry) or (ts_us := _ts_us(entry.get("__REALTIME_TIMESTAMP"))) is None:
        return None
    common: dict[str, Any] = {
        "ts_us": ts_us,
        "unit": str(entry["UNIT"]),
        "invocation_id": _str(entry, "INVOCATION_ID"),
    }
    match _message_id(entry.get("MESSAGE_ID")):
        case "d9b373ed55a64feb8242e02dbe79a49c":
            return UnitEvent(kind="failed", result=_str(entry, "UNIT_RESULT"), **common)
        case "98e322203f7a4ed290d09fe03c09fe15":
            return UnitEvent(
                kind="exited",
                exit_code=_str(entry, "EXIT_CODE"),
                exit_status=_str(entry, "EXIT_STATUS"),
                **common,
            )
        case "be02cf6855d2428ba40df7e9d022f03d":
            return UnitEvent(kind="start_failed", result=_str(entry, "JOB_RESULT"), **common)
    return None


class JournalCollector:
    def __init__(
        self,
        queue: EventQueue,
        reader_factory: Callable[[], ReaderLike] = open_reader,
        on_unit_change: Callable[[], None] = lambda: None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._queue = queue
        self._factory = reader_factory
        self._on_unit_change = on_unit_change
        self._monotonic = monotonic
        self._reader: ReaderLike | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._state = "starting"
        self._last_hint = float("-inf")
        self._hint_timer: asyncio.TimerHandle | None = None

    def health(self) -> dict[str, object]:
        return {"state": self._state}

    def _open(self) -> ReaderLike:
        reader = self._factory()
        reader.this_boot()
        reader.add_match(_PID="1")
        reader.seek_tail()
        reader.get_previous()  # standard idiom: get_next() now yields only new entries
        return reader

    def _hint(self) -> None:
        """Tell the PSI collector units changed, at most once per HINT_INTERVAL."""
        if self._hint_timer is not None:
            return
        wait = self._last_hint + HINT_INTERVAL - self._monotonic()
        if wait <= 0:
            self._last_hint = self._monotonic()
            self._on_unit_change()
        else:  # trailing call, so the last change in a burst is not lost
            self._hint_timer = asyncio.get_running_loop().call_later(wait, self._fire_hint)

    def _fire_hint(self) -> None:
        self._hint_timer = None
        self._last_hint = self._monotonic()
        self._on_unit_change()

    def _drain(self) -> None:
        if (reader := self._reader) is None:
            return
        for _ in range(MAX_PER_WAKEUP):
            if not (entry := reader.get_next()):
                return
            if (ev := entry_to_event(entry)) is not None:
                self._queue.put_nowait(ev)
            elif _from_systemd(entry):
                self._hint()
        asyncio.get_running_loop().call_soon(self._drain_safely)

    def _drain_safely(self) -> None:
        try:
            self._drain()
        except Exception:
            log.exception("journal drain failed")

    def _on_readable(self) -> None:
        if (reader := self._reader) is None:
            return
        try:
            reader.process()
            self._drain()
        except Exception:
            log.exception("journal wakeup failed")

    def close(self) -> None:
        if self._hint_timer is not None:
            self._hint_timer.cancel()
            self._hint_timer = None
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    async def run(self) -> None:
        loop = self._loop = asyncio.get_running_loop()
        try:
            self._reader = self._open()
            loop.add_reader(self._reader.fileno(), self._on_readable)
        except Exception:
            log.exception("journal collector could not start")
            self._state = "error"
            self.close()
            return
        self._state = "ok"
        fd = self._reader.fileno()
        try:
            await asyncio.Event().wait()
        finally:
            loop.remove_reader(fd)
            self.close()


def unit_tail(
    unit: str, n: int, reader_factory: Callable[[], ReaderLike] = open_reader
) -> list[dict[str, Any]]:
    """The last n journal lines for a unit this boot, oldest first.

    Blocking I/O: call it from a thread (asyncio.to_thread).
    """
    reader = reader_factory()
    try:
        reader.add_match(_SYSTEMD_UNIT=unit)
        reader.add_disjunction()
        reader.add_match(UNIT=unit, _PID="1")
        reader.this_boot()
        reader.seek_tail()
        lines: list[dict[str, Any]] = []
        for _ in range(n):
            if not (entry := reader.get_previous()):
                break
            lines.append(
                {
                    "ts_us": _ts_us(entry.get("__REALTIME_TIMESTAMP")) or 0,
                    "priority": int(entry.get("PRIORITY", 6)),
                    "message": _text(entry.get("MESSAGE", "")),
                }
            )
        return lines[::-1]
    finally:
        reader.close()
