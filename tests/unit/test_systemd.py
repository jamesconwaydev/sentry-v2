"""SystemdManager contract, run against FakeSystemd here and DBusSystemd on a host."""

from __future__ import annotations

import asyncio

import pytest

from sentry_v2.systemd import (
    UNSET,
    FakeSystemd,
    SystemdError,
    SystemdManager,
    UnitNotFound,
    UnitProps,
    _props_from_dbus,
    _translate,
)

run = asyncio.run


class SystemdContract:
    """Subclasses provide `manager` and `unit` fixtures; the unit must be running."""

    def test_set_then_get(self, manager: SystemdManager, unit: str) -> None:
        run(manager.set_properties(unit, 32 * 1024 * 1024, 50))
        p = run(manager.get_properties(unit))
        assert p.memory_high == 32 * 1024 * 1024
        assert p.cpu_weight == 50

    def test_none_leaves_property_alone(self, manager: SystemdManager, unit: str) -> None:
        run(manager.set_properties(unit, 32 * 1024 * 1024, 50))
        run(manager.set_properties(unit, None, 70))
        p = run(manager.get_properties(unit))
        assert (p.memory_high, p.cpu_weight) == (32 * 1024 * 1024, 70)

    def test_rollback_to_raw_values(self, manager: SystemdManager, unit: str) -> None:
        before = run(manager.get_properties(unit))
        run(manager.set_properties(unit, 32 * 1024 * 1024, 50))
        run(manager.set_properties(unit, before.memory_high, before.cpu_weight))
        after = run(manager.get_properties(unit))
        assert (after.memory_high, after.cpu_weight) == (before.memory_high, before.cpu_weight)

    def test_freeze_thaw(self, manager: SystemdManager, unit: str) -> None:
        run(manager.freeze(unit))
        assert run(manager.get_properties(unit)).freezer_state == "frozen"
        run(manager.thaw(unit))
        assert run(manager.get_properties(unit)).freezer_state == "running"

    def test_reload_keeps_unit_active(self, manager: SystemdManager, unit: str) -> None:
        run(manager.reload(unit))
        assert run(manager.get_properties(unit)).active_state in ("active", "reloading")

    def test_properties_shape(self, manager: SystemdManager, unit: str) -> None:
        p = run(manager.get_properties(unit))
        assert p.main_pid > 0
        assert p.cgroup and not p.cgroup.startswith("/")
        assert p.exec_start

    def test_unknown_unit(self, manager: SystemdManager) -> None:
        name = "sentry-test-nope.service"
        for call in (
            lambda: manager.get_properties(name),
            lambda: manager.set_properties(name, 1, None),
            lambda: manager.freeze(name),
            lambda: manager.thaw(name),
            lambda: manager.reload(name),
        ):
            with pytest.raises(UnitNotFound):
                run(call())


NGINX = UnitProps(
    memory_high=UNSET,
    cpu_weight=UNSET,
    freezer_state="running",
    active_state="active",
    main_pid=42,
    fragment_path="/usr/lib/systemd/system/nginx.service",
    drop_in_paths=(),
    exec_start=("/usr/sbin/nginx",),
    cgroup="system.slice/nginx.service",
)


class TestFake(SystemdContract):
    @pytest.fixture
    def manager(self) -> FakeSystemd:
        return FakeSystemd({"nginx.service": NGINX})

    @pytest.fixture
    def unit(self) -> str:
        return "nginx.service"

    def test_records_calls(self, manager: FakeSystemd, unit: str) -> None:
        run(manager.set_properties(unit, 5, None))
        run(manager.freeze(unit))
        assert manager.calls == [("set_properties", unit, "5", "None"), ("freeze", unit)]

    def test_injected_failure(self, manager: FakeSystemd, unit: str) -> None:
        manager.fail["freeze"] = SystemdError("org.x.Boom", "no")
        with pytest.raises(SystemdError):
            run(manager.freeze(unit))
        assert manager.calls == [("freeze", unit)]
        assert run(manager.get_properties(unit)).freezer_state == "running"


def test_translate() -> None:
    assert isinstance(_translate("org.freedesktop.systemd1.NoSuchUnit", "x", "a"), UnitNotFound)
    assert isinstance(
        _translate("org.freedesktop.DBus.Error.UnknownObject", "x", "a"), UnitNotFound
    )
    e = _translate("org.freedesktop.systemd1.Boom", "bad", "a")
    assert isinstance(e, SystemdError) and e.name.endswith("Boom") and e.message == "bad"


def test_props_from_dbus() -> None:
    unit = {
        "FragmentPath": "/usr/lib/systemd/system/a.service",
        "DropInPaths": ["/etc/systemd/system/a.service.d/x.conf"],
        "ActiveState": "active",
        "FreezerState": "running",
    }
    typed = {
        "MemoryHigh": 2**64 - 1,
        "CPUWeight": 100,
        "MainPID": 7,
        "ControlGroup": "/system.slice/a.service",
        "ExecStart": [["/bin/a", ["a", "-x"], False, 0, 0, 0, 0, 0, 0, 0]],
    }
    assert _props_from_dbus(unit, typed) == UnitProps(
        memory_high=2**64 - 1,
        cpu_weight=100,
        freezer_state="running",
        active_state="active",
        main_pid=7,
        fragment_path="/usr/lib/systemd/system/a.service",
        drop_in_paths=("/etc/systemd/system/a.service.d/x.conf",),
        exec_start=("/bin/a",),
        cgroup="system.slice/a.service",
    )


def test_props_from_dbus_missing_optional() -> None:
    p = _props_from_dbus({"ActiveState": "inactive"}, {})
    assert p.memory_high == UNSET and p.exec_start == () and p.cgroup == ""
