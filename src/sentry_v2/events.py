"""Event and incident records passed between collectors, correlation and sinks."""

from __future__ import annotations

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
    exit_status: int | None = None
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
    permissive: bool = False
    cgroup_at_receipt: str | None = None
    unit_at_receipt: str | None = None
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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
