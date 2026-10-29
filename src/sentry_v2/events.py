"""Event and incident records passed between collectors, correlation and sinks."""

from __future__ import annotations

import asyncio
from collections import Counter, deque
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True)
class PressureLine:
    avg10: float
    avg60: float
    avg300: float
    total_us: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class PsiEvent:
    ts_us: int
    source: str = "psi"
    cgroup: str
    resource: Literal["memory", "cpu", "io"]
    kind: Literal["some", "full"]
    avg10: float
    avg60: float
    avg300: float
    total_us: int
    triggered: bool
    stall_us: int | None = None  # trigger threshold; None on periodic samples
    window_us: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class UnitEvent:
    ts_us: int
    source: str = "journal"
    unit: str
    kind: Literal["failed", "exited", "start_failed"]
    result: str | None = None  # e.g. "watchdog", "timeout", "exit-code"
    exit_code: str | None = None
    exit_status: str | None = None  # "1", or a signal name such as "SEGV"
    invocation_id: str | None = None
    main_pid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class AvcEvent:
    ts_us: int
    source: str = "audit"
    serial: int
    denied: bool
    perms: tuple[str, ...]
    scontext: str
    scontext_type: str
    tcontext: str
    tclass: str
    comm: str | None = None
    exe: str | None = None
    pid: int | None = None
    ppid: int | None = None
    permissive: bool = False
    cgroup_at_receipt: str | None = None
    unit_at_receipt: str | None = None
    # read only when the process had already exited
    parent_cgroup_at_receipt: str | None = None
    parent_unit_at_receipt: str | None = None
    raw: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


Event = PsiEvent | UnitEvent | AvcEvent


@dataclass(frozen=True)
class Correlation:
    avc: AvcEvent
    confidence: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Incident:
    id: str
    kind: Literal["unit_failed", "psi", "avc"]
    ts_us: int
    target: str
    trigger: Event
    related: tuple[Event, ...]
    correlations: tuple[Correlation, ...]
    sustained: float | None = None  # psi only: the policy period the stall outlasted
    audit_caught_up: bool = True  # unit_failed only: False if denials may be missing

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class EventQueue:
    """Bounded queue between collectors and the correlator.

    A full queue drops its oldest event so collectors never block; drops are
    counted per source.
    """

    def __init__(self, maxlen: int = 10_000) -> None:
        self._q: deque[Event] = deque(maxlen=maxlen)
        self._ready = asyncio.Event()
        self.dropped: Counter[str] = Counter()

    def __len__(self) -> int:
        return len(self._q)

    def put_nowait(self, ev: Event) -> None:
        if len(self._q) == self._q.maxlen:
            self.dropped[self._q[0].source] += 1
        self._q.append(ev)
        self._ready.set()

    async def get(self) -> Event:
        while not self._q:
            self._ready.clear()
            await self._ready.wait()
        return self._q.popleft()
