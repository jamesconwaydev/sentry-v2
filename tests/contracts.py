"""Shared SystemdManager contract; run by the fake (unit) and DBusSystemd (integration)."""

from __future__ import annotations

import asyncio

import pytest

from sentry_v2.systemd import UNSET, SystemdError, SystemdManager, UnitNotFound, UnitProps

run = asyncio.run


class SystemdContract:
    """Subclasses provide `manager`, `unit` (running) and `inactive_unit` (loaded, not active)."""

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

    def test_freeze_of_inactive_unit_raises(
        self, manager: SystemdManager, inactive_unit: str
    ) -> None:
        with pytest.raises(SystemdError):
            run(manager.freeze(inactive_unit))

    def test_freeze_thaw(self, manager: SystemdManager, unit: str) -> None:
        run(manager.freeze(unit))
        assert run(manager.get_properties(unit)).freezer_state in ("frozen", "frozen-by-parent")
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
