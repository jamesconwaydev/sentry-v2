"""Policy model, the protected-unit list and the engine that plans actions."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal

from .events import AvcEvent, Incident, PsiEvent, UnitEvent
from .units import Percent

Mode = Literal["dry-run", "enforce"]

PROTECTED: frozenset[str] = frozenset(
    {
        "init.scope",
        "-.slice",
        "system.slice",
        "user.slice",
        "sshd.service",
        "systemd-journald.service",
        "dbus-broker.service",
        "dbus.service",
        "systemd-logind.service",
        "auditd.service",
        "sentry-v2.service",
        "systemd-*.service",
    }
)


def is_protected(unit: str, extra: Iterable[str]) -> bool:
    """True if `unit` matches a built-in protected pattern or one in `extra`."""
    return any(fnmatchcase(unit, p) for p in (*PROTECTED, *extra))


@dataclass(frozen=True)
class PsiWhen:
    resource: Literal["memory", "cpu", "io"]
    kind: Literal["some", "full"]
    stall_us: int
    window_us: int
    sustained: float
    cgroups: tuple[str, ...]


@dataclass(frozen=True)
class UnitFailedWhen:
    units: tuple[str, ...]
    results: tuple[str, ...] = ()


@dataclass(frozen=True)
class AvcWhen:
    scontext_types: tuple[str, ...] = ()
    min_count: int = 1


@dataclass(frozen=True)
class Throttle:
    memory_high: int | Percent | None
    cpu_weight: int | None
    duration: float


@dataclass(frozen=True)
class Freeze:
    duration: float
    release_below: float | None = None


@dataclass(frozen=True)
class BackupReload:
    paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class Notify:
    pass


ActionSpec = Throttle | Freeze | BackupReload | Notify
When = PsiWhen | UnitFailedWhen | AvcWhen


@dataclass(frozen=True)
class Policy:
    name: str
    mode: Mode
    cooldown: float
    when: When
    actions: tuple[ActionSpec, ...]
    source: Path


def target_matches(pattern: str, path: str) -> bool:
    """Match a policy pattern against a cgroup path or unit name.

    A pattern containing "/" matches the whole path relative to the cgroup
    root (`system.slice/batch-*.service`); one without matches only the last
    path component, i.e. the unit name (`nginx.service`).
    """
    path = path.strip("/")
    if "/" in pattern:
        return fnmatchcase(path, pattern)
    return fnmatchcase(path.rsplit("/", 1)[-1], pattern)


def effective_mode(daemon_mode: Mode, policy_mode: Mode) -> Mode:
    """Enforce only when both the daemon and the policy say so."""
    return "enforce" if daemon_mode == policy_mode == "enforce" else "dry-run"


def _matches(incident: Incident, when: When) -> bool:
    trigger = incident.trigger
    match when:
        case PsiWhen():
            return (
                incident.kind == "psi"
                and isinstance(trigger, PsiEvent)
                and trigger.resource == when.resource
                and trigger.kind == when.kind
                and trigger.stall_us == when.stall_us
                and trigger.window_us == when.window_us
                and incident.sustained == when.sustained
                and any(target_matches(p, incident.target) for p in when.cgroups)
            )
        case UnitFailedWhen():
            return (
                incident.kind == "unit_failed"
                and any(target_matches(p, incident.target) for p in when.units)
                and (not when.results or _result(trigger) in when.results)
            )
        case AvcWhen():
            avcs = [e for e in {trigger, *incident.related} if isinstance(e, AvcEvent)]
            if when.scontext_types:
                avcs = [a for a in avcs if a.scontext_type in when.scontext_types]
            return incident.kind == "avc" and len(avcs) >= when.min_count


def _result(event: object) -> str | None:
    return event.result if isinstance(event, UnitEvent) else None


class PolicyEngine:
    """Decides which policy actions an incident triggers, honouring cooldowns.

    The cooldown for (policy, target) is stamped when an action is planned,
    not when it completes or succeeds.
    """

    def __init__(self, policies: Iterable[Policy], clock: Callable[[], float]) -> None:
        self._policies = tuple(policies)
        self._clock = clock
        self._last: dict[tuple[str, str], float] = {}

    def replace(self, policies: Iterable[Policy]) -> None:
        """Swap the policy set; cooldown history is kept."""
        self._policies = tuple(policies)

    def plan(self, incident: Incident) -> list[tuple[Policy, ActionSpec]]:
        now = self._clock()
        longest = max((p.cooldown for p in self._policies), default=0.0)
        self._last = {k: t for k, t in self._last.items() if now - t < longest}
        planned: list[tuple[Policy, ActionSpec]] = []
        for policy in self._policies:
            if not _matches(incident, policy.when):
                continue
            key = (policy.name, incident.target)
            last = self._last.get(key)
            if last is not None and now - last < policy.cooldown:
                continue
            self._last[key] = now
            planned.extend((policy, action) for action in policy.actions)
        return planned
