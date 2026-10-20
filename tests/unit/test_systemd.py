"""SystemdManager contract, run against FakeSystemd here and DBusSystemd on a host."""

from __future__ import annotations

import asyncio
import dataclasses

import pytest

from contracts import NGINX, SystemdContract
from sentry_v2.systemd import (
    UNSET,
    DBusSystemd,
    FakeSystemd,
    SystemdError,
    UnitNotFound,
    UnitProps,
    _iface_for,
    _props_from_dbus,
    _translate,
    slice_cgroup,
)

run = asyncio.run


class TestFake(SystemdContract):
    @pytest.fixture
    def manager(self) -> FakeSystemd:
        return FakeSystemd({"nginx.service": NGINX})

    @pytest.fixture
    def unit(self) -> str:
        return "nginx.service"

    @pytest.fixture
    def inactive_unit(self, manager: FakeSystemd) -> str:
        manager.units["dead.service"] = dataclasses.replace(NGINX, active_state="failed")
        return "dead.service"

    def test_reload_not_applicable(self, manager: FakeSystemd, unit: str) -> None:
        manager.reloadable[unit] = False
        with pytest.raises(SystemdError, match="JobTypeNotApplicable"):
            run(manager.reload(unit))

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
        "Slice": "system.slice",
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
        slice="system.slice",
    )


def test_props_from_dbus_missing_optional() -> None:
    p = _props_from_dbus({"ActiveState": "inactive"}, {})
    assert p.memory_high == UNSET and p.exec_start == () and p.cgroup == ""


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("system.slice", "system.slice"),
        ("sentry-test.slice", "sentry.slice/sentry-test.slice"),
        ("user-1000.slice", "user.slice/user-1000.slice"),
        ("a-b-c.slice", "a.slice/a-b.slice/a-b-c.slice"),
        ("-.slice", ""),
    ],
)
def test_slice_cgroup(name: str, path: str) -> None:
    assert slice_cgroup(name) == path


def test_iface_for() -> None:
    assert [_iface_for(f"a{s}") for s in (".service", ".socket", ".mount", ".swap")] == [
        "Service", "Socket", "Mount", "Swap"
    ]  # fmt: skip
    with pytest.raises(SystemdError, match="UnsupportedUnitType"):
        _iface_for("a.timer")


def test_call_after_close_raises_closed() -> None:
    m = DBusSystemd()
    m.close()
    m.close()  # idempotent
    with pytest.raises(SystemdError, match="Closed"):
        run(m.freeze("a.service"))


def test_fake_refuses_unsupported_suffix() -> None:
    with pytest.raises(SystemdError, match="UnsupportedUnitType"):
        run(FakeSystemd().get_properties("a.timer"))
