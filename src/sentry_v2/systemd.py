"""systemd over D-Bus: property reads, runtime limits, freeze/thaw and reload.

All real bus traffic happens on one worker thread (dbus-python objects must
stay on the thread that made them). FakeSystemd stands in for tests and for
`policy test`.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol

# MemoryHigh "infinity" and CPUWeight "unset" are both the maximum uint64.
# Verified on systemd 257: SetUnitProperties accepts UInt64(2**64-1) for CPUWeight
# and restores the unset state, so rollback can replay the raw value.
UNSET = 2**64 - 1

_DEST = "org.freedesktop.systemd1"
_NOT_FOUND = {f"{_DEST}.NoSuchUnit", "org.freedesktop.DBus.Error.UnknownObject"}
_TYPED_IFACE = {".service": "Service", ".scope": "Scope", ".slice": "Slice"}


class UnitNotFound(Exception):
    """The unit is not known (or not loaded) in systemd."""


class SystemdError(Exception):
    """Any other D-Bus failure, carrying the D-Bus error name."""

    def __init__(self, name: str, message: str) -> None:
        super().__init__(f"{name}: {message}")
        self.name = name
        self.message = message


@dataclass(frozen=True)
class UnitProps:
    """Raw values as systemd reports them, so a rollback restores exactly."""

    memory_high: int
    cpu_weight: int
    freezer_state: str
    active_state: str
    main_pid: int
    fragment_path: str
    drop_in_paths: tuple[str, ...]
    exec_start: tuple[str, ...]
    cgroup: str  # relative to the cgroup root, like CgroupFS paths


class SystemdManager(Protocol):
    async def get_properties(self, unit: str) -> UnitProps: ...
    async def set_properties(
        self, unit: str, memory_high: int | None, cpu_weight: int | None
    ) -> None: ...
    async def freeze(self, unit: str) -> None: ...
    async def thaw(self, unit: str) -> None: ...
    async def reload(self, unit: str) -> None: ...


def _props_from_dbus(unit_props: Mapping[str, Any], typed_props: Mapping[str, Any]) -> UnitProps:
    """Map GetAll results (Unit interface, Service/Scope/Slice interface) to UnitProps."""
    return UnitProps(
        memory_high=int(typed_props.get("MemoryHigh", UNSET)),
        cpu_weight=int(typed_props.get("CPUWeight", UNSET)),
        freezer_state=str(unit_props.get("FreezerState", "")),
        active_state=str(unit_props.get("ActiveState", "")),
        main_pid=int(typed_props.get("MainPID", 0)),
        fragment_path=str(unit_props.get("FragmentPath", "")),
        drop_in_paths=tuple(str(p) for p in unit_props.get("DropInPaths", ())),
        # ExecStart is a(sasbttttuii): the first field of each entry is the binary path
        exec_start=tuple(str(e[0]) for e in typed_props.get("ExecStart", ())),
        cgroup=str(typed_props.get("ControlGroup", "")).lstrip("/"),
    )


def _translate(name: str, message: str, unit: str) -> Exception:
    if name in _NOT_FOUND:
        return UnitNotFound(unit)
    return SystemdError(name, message)


class DBusSystemd:
    """Talks to systemd1 on the system bus from a single-thread executor."""

    def __init__(self, executor: ThreadPoolExecutor) -> None:
        self._ex = executor
        self._bus: Any = None

    async def _run(self, unit: str, fn: Callable[[Any, Any], Any]) -> Any:  # pragma: no cover
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._ex, self._call, unit, fn)

    def _call(self, unit: str, fn: Callable[[Any, Any], Any]) -> Any:  # pragma: no cover
        import dbus  # distro binding, imported lazily so macOS can import the package

        if self._bus is None:
            self._bus = dbus.SystemBus()  # created on the worker thread, reused there
        mgr = dbus.Interface(
            self._bus.get_object(_DEST, "/org/freedesktop/systemd1"), f"{_DEST}.Manager"
        )
        try:
            return fn(mgr, dbus)
        except dbus.exceptions.DBusException as e:
            raise _translate(e.get_dbus_name(), e.get_dbus_message(), unit) from e

    async def get_properties(self, unit: str) -> UnitProps:  # pragma: no cover
        def read(mgr: Any, dbus: Any) -> UnitProps:
            # GetUnit, not LoadUnit: reading must never load arbitrary unit files
            obj = self._bus.get_object(_DEST, mgr.GetUnit(unit))
            props = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
            typed = {}
            if iface := next((i for s, i in _TYPED_IFACE.items() if unit.endswith(s)), None):
                typed = props.GetAll(f"{_DEST}.{iface}")
            return _props_from_dbus(props.GetAll(f"{_DEST}.Unit"), typed)

        return await self._run(unit, read)  # type: ignore[no-any-return]

    async def set_properties(
        self, unit: str, memory_high: int | None, cpu_weight: int | None
    ) -> None:  # pragma: no cover
        def write(mgr: Any, dbus: Any) -> None:
            props = []
            if memory_high is not None:
                props.append(("MemoryHigh", dbus.UInt64(memory_high)))
            if cpu_weight is not None:
                props.append(("CPUWeight", dbus.UInt64(cpu_weight)))
            mgr.SetUnitProperties(unit, True, dbus.Array(props, signature="(sv)"))

        await self._run(unit, write)

    async def freeze(self, unit: str) -> None:  # pragma: no cover
        await self._run(unit, lambda mgr, _d: mgr.FreezeUnit(unit))

    async def thaw(self, unit: str) -> None:  # pragma: no cover
        await self._run(unit, lambda mgr, _d: mgr.ThawUnit(unit))

    async def reload(self, unit: str) -> None:  # pragma: no cover
        await self._run(unit, lambda mgr, _d: mgr.ReloadUnit(unit, "replace"))


@dataclass
class FakeSystemd:
    """In-memory SystemdManager. `fail[method]` is raised by that method."""

    units: dict[str, UnitProps] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)
    fail: dict[str, Exception] = field(default_factory=dict)

    def _enter(self, method: str, unit: str, *args: object) -> UnitProps:
        self.calls.append((method, unit, *map(str, args)))
        if method in self.fail:
            raise self.fail[method]
        if unit not in self.units:
            raise UnitNotFound(unit)
        return self.units[unit]

    async def get_properties(self, unit: str) -> UnitProps:
        return self._enter("get_properties", unit)

    async def set_properties(
        self, unit: str, memory_high: int | None, cpu_weight: int | None
    ) -> None:
        cur = self._enter("set_properties", unit, memory_high, cpu_weight)
        self.units[unit] = dataclasses.replace(
            cur,
            memory_high=cur.memory_high if memory_high is None else memory_high,
            cpu_weight=cur.cpu_weight if cpu_weight is None else cpu_weight,
        )

    async def freeze(self, unit: str) -> None:
        cur = self._enter("freeze", unit)
        self.units[unit] = dataclasses.replace(cur, freezer_state="frozen")

    async def thaw(self, unit: str) -> None:
        cur = self._enter("thaw", unit)
        self.units[unit] = dataclasses.replace(cur, freezer_state="running")

    async def reload(self, unit: str) -> None:
        self._enter("reload", unit)
