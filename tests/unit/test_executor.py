import asyncio
import dataclasses
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import PRESSURE
from contracts import NGINX
from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.config_types import LimitsConfig, ProtectionConfig
from sentry_v2.events import AvcEvent, Incident, PsiEvent, UnitEvent
from sentry_v2.executor import Executor
from sentry_v2.policy import (
    ActionSpec,
    AvcWhen,
    BackupReload,
    Freeze,
    Mode,
    Notify,
    Policy,
    PsiWhen,
    Throttle,
    UnitFailedWhen,
)
from sentry_v2.state import ActionJournal, ActionRecord
from sentry_v2.systemd import UNSET, FakeSystemd, SystemdError, UnitNotFound
from sentry_v2.units import Percent

MiB = 1024**2
UNIT = "batch-1.service"
CG = "system.slice/batch-1.service"
WHEN = PsiWhen("memory", "some", 150_000, 1_000_000, 0.0, ("system.slice/batch-*.service",))


class FakeClock:
    """Wall and monotonic clocks that only move when a test calls advance().

    Sleepers wake on the monotonic timeline, like asyncio.sleep; a test can
    step `now` (wall time) on its own to simulate a clock change.
    """

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now
        self.mono = 0.0
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def __call__(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.mono

    async def sleep(self, delay: float) -> None:
        fut = asyncio.get_running_loop().create_future()
        self._sleepers.append((self.mono + delay, fut))
        await fut

    async def advance(self, delta: float) -> None:
        """Move both clocks forward, waking each sleeper in deadline order."""
        target = self.mono + delta
        await settle()
        while due := sorted((s for s in self._sleepers if s[0] <= target), key=lambda s: s[0]):
            deadline, fut = due[0]
            self._sleepers.remove(due[0])
            step = max(0.0, deadline - self.mono)
            self.mono += step
            self.now += step
            if not fut.done():  # cancelled sleepers leave a done future
                fut.set_result(None)
            await settle()
        self.now += target - self.mono
        self.mono = target
        await settle()


async def settle() -> None:
    for _ in range(50):
        await asyncio.sleep(0)


def unit_props(name: str) -> Any:
    return dataclasses.replace(NGINX, cgroup=f"system.slice/{name}", fragment_path="")


def policy(*actions: ActionSpec, mode: Mode = "enforce", when: Any = WHEN) -> Policy:
    return Policy("pol", mode, 0.0, when, actions, Path("/etc/p.toml"))


def psi_incident(cg: str = CG) -> Incident:
    ev = PsiEvent(
        ts_us=1, cgroup=cg, resource="memory", kind="some",
        avg10=42, avg60=0, avg300=0, total_us=0, triggered=True,
    )  # fmt: skip
    return Incident("inc-1", "psi", 1, cg, ev, (), ())


def stored(**kw: Any) -> ActionRecord:
    """A journal record as a previous run would have left it."""
    base = {
        "id": "r1", "policy": "pol", "action": "throttle", "target": UNIT, "mode": "enforce",
        "status": "applied", "previous": {}, "applied_at": 1.0, "expires_at": 61.0,
        "error": None, "incident_id": "i",
    }  # fmt: skip
    return ActionRecord(**{**base, **kw})


class Harness:
    def __init__(self, base: Path, *, mode: Mode = "enforce", **limits: Any) -> None:
        self.clock = FakeClock()
        self.mgr = FakeSystemd(units={u: unit_props(u) for u in (UNIT, "batch-2.service")})
        self.fs = CgroupFS(base / "cgroup", base / "proc")
        self.journal_path = base / "state" / "state" / "actions.jsonl"
        self.journal = ActionJournal(self.journal_path, clock=self.clock)
        self.notified: list[tuple[Incident, list[ActionRecord]]] = []
        self.alerts: list[tuple[str, dict[str, Any]]] = []
        self.ex = Executor(
            self.mgr, self.fs, self.journal, LimitsConfig(**limits),
            ProtectionConfig(("extra-*.service",)), self.notify, self.alert,
            self.clock, base / "state" / "backups", daemon_mode=mode, sleep=self.clock.sleep,
            monotonic=self.clock.monotonic,
        )  # fmt: skip

    async def notify(self, inc: Incident, recs: list[ActionRecord]) -> None:
        self.notified.append((inc, recs))

    async def alert(self, kind: str, detail: dict[str, Any]) -> None:
        self.alerts.append((kind, detail))

    def dbus_writes(self) -> list[tuple[str, ...]]:
        return [c for c in self.mgr.calls if c[0] != "get_properties"]

    def statuses(self) -> list[tuple[str, str]]:
        lines = self.journal_path.read_text().splitlines()
        return [(json.loads(x)["action"], json.loads(x)["status"]) for x in lines]


def run(fn: Callable[[], Awaitable[None]]) -> None:
    asyncio.run(fn())  # type: ignore[arg-type]


@pytest.fixture
def h(fake_cgroupfs: Path) -> Harness:
    return Harness(fake_cgroupfs)


def test_enforce_throttle_journals_before_dbus_then_rolls_back(h: Harness) -> None:
    seen: list[list[tuple[str, str]]] = []
    real_set = h.mgr.set_properties

    async def spy(unit: str, mh: int | None, cw: int | None) -> None:
        seen.append(h.statuses())
        await real_set(unit, mh, cw)

    h.mgr.set_properties = spy  # type: ignore[method-assign]

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, 10, 60))])
        assert seen[0] == [("throttle", "planned")]
        assert rec.status == "applied" and rec.mode == "enforce"
        assert rec.previous == {"memory_high": UNSET, "cpu_weight": UNSET}
        assert rec.expires_at == h.clock.now + 60
        assert h.mgr.units[UNIT].memory_high == 64 * MiB
        assert [r.id for r in h.ex.active()] == [rec.id]
        await h.clock.advance(59)
        assert h.mgr.units[UNIT].memory_high == 64 * MiB
        await h.clock.advance(2)
        assert (h.mgr.units[UNIT].memory_high, h.mgr.units[UNIT].cpu_weight) == (UNSET, UNSET)
        assert h.journal.load()[rec.id].status == "rolled_back"
        assert h.ex.active() == []

    run(main)
    assert h.statuses() == [
        ("throttle", "planned"),
        ("throttle", "applied"),
        ("throttle", "rolled_back"),
    ]


def test_duration_clamped_to_max(fake_cgroupfs: Path) -> None:
    h = Harness(fake_cgroupfs, max_action_duration=30.0)

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(600))])
        assert rec.expires_at == h.clock.now + 30
        await h.ex.shutdown()

    run(main)


@pytest.mark.parametrize("mode", ["dry-run", "enforce"])
def test_dry_run_makes_no_dbus_calls(fake_cgroupfs: Path, mode: Mode) -> None:
    # daemon dry-run with policy enforce, and daemon enforce with policy dry-run
    h = Harness(fake_cgroupfs, mode=mode)
    pol = policy(Throttle(64 * MiB, None, 60), Freeze(60), BackupReload(), Notify(),
                 mode="enforce" if mode == "dry-run" else "dry-run")  # fmt: skip

    async def main() -> None:
        recs = await h.ex.handle(psi_incident(), [(pol, a) for a in pol.actions])
        assert {r.status for r in recs} == {"dry_run"}
        assert recs[0].configured_mode == pol.mode
        assert recs[0].params == {"memory_high": 64 * MiB, "cpu_weight": None}
        assert h.notified == [(psi_incident(), recs)]

    run(main)
    assert h.mgr.calls == []


def test_protected_target_untouched(h: Harness) -> None:
    async def main() -> None:
        recs = await h.ex.handle(
            psi_incident("system.slice/sshd.service"), [(policy(), Freeze(60))]
        )
        recs += await h.ex.handle(
            psi_incident("system.slice/extra-1.service"), [(policy(), Freeze(60))]
        )
        assert [(r.status, r.error) for r in recs] == [("failed", "protected")] * 2

    run(main)
    assert h.mgr.calls == []


def test_avc_incident_only_notifies(h: Harness) -> None:
    avc = AvcEvent(
        ts_us=1, serial=1, denied=True, perms=("read",), scontext="s", scontext_type="httpd_t",
        tcontext="t", tclass="file",
    )  # fmt: skip
    inc = Incident("inc-2", "avc", 1, "httpd_t", avc, (), ())
    pol = policy(Freeze(60), Notify(), when=AvcWhen())

    async def main() -> None:
        recs = await h.ex.handle(inc, [(pol, a) for a in pol.actions])
        assert [(r.action, r.status, r.error) for r in recs] == [
            ("freeze", "failed", "no unit target"),
            ("notify", "applied", None),
        ]
        assert len(h.notified) == 1

    run(main)
    assert h.mgr.calls == []


def test_replay_thaws_applied_freeze(h: Harness) -> None:
    h.mgr.units[UNIT] = dataclasses.replace(h.mgr.units[UNIT], freezer_state="frozen")
    crashed = stored(id="f1", action="freeze", previous={"freezer_state": "running"})
    h.journal.append(crashed)
    h.journal.append(
        dataclasses.replace(crashed, id="b1", action="backup_reload", status="planned")
    )

    async def main() -> None:
        await h.ex.replay()

    run(main)
    assert h.mgr.calls == [("thaw", UNIT)]
    loaded = h.journal.load()
    assert loaded["f1"].status == "rolled_back"
    assert (loaded["b1"].status, loaded["b1"].error) == ("failed", "interrupted")


def test_replay_unit_gone_no_retry(h: Harness) -> None:
    h.journal.append(
        stored(id="t1", target="gone.service", status="planned", previous={"memory_high": UNSET})
    )

    async def main() -> None:
        await h.ex.replay()

    run(main)
    assert len(h.mgr.calls) == 1
    rec = h.journal.load()["t1"]
    assert (rec.status, rec.error) == ("rolled_back", "unit gone")


def test_replay_compacts_old_closed_records(h: Harness) -> None:
    h.clock.now = 0
    h.journal.append(stored(id="old", action="notify", expires_at=None))
    h.clock.now = 8 * 86400

    async def main() -> None:
        await h.ex.replay()

    run(main)
    assert h.journal.load() == {}


def test_rollback_failing_ten_times_alerts_once(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        h.mgr.fail["thaw"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "no reply")
        await h.clock.advance(60)
        await h.clock.advance(1 + 2 + 4 + 8 + 16 + 32 + 60 + 60 + 59)
        assert h.journal.load()[rec.id].status == "applied"
        await h.clock.advance(1)
        final = h.journal.load()[rec.id]
        assert final.status == "rollback_failed"
        assert "NoReply" in (final.error or "")
        assert [a[0] for a in h.alerts] == ["rollback_failed"]
        assert h.alerts[0][1]["record"]["id"] == rec.id
        await h.clock.advance(600)
        assert len(h.alerts) == 1

    run(main)
    assert [c[0] for c in h.mgr.calls].count("thaw") == 10


def test_breaker_forces_dry_run_then_closes(h: Harness) -> None:
    h.mgr.fail["freeze"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "no")
    plan = [(policy(), Freeze(60))]

    async def main() -> None:
        for _ in range(3):
            [rec] = await h.ex.handle(psi_incident(), plan)
            assert rec.status == "planned" and "NoReply" in (rec.error or "")
            await h.clock.advance(60)
            assert h.journal.load()[rec.id].status == "rolled_back"
        assert h.ex.breaker_state()["open"] is True
        assert [a[0] for a in h.alerts] == ["breaker_open"]
        del h.mgr.fail["freeze"]
        [rec] = await h.ex.handle(psi_incident(), plan)
        assert (rec.status, rec.mode, rec.configured_mode) == ("dry_run", "dry-run", "enforce")
        await h.clock.advance(15 * 60)
        assert h.ex.breaker_state()["open"] is False
        [rec] = await h.ex.handle(psi_incident(), plan)
        assert rec.status == "applied"
        await h.ex.shutdown()

    run(main)


def test_breaker_ignores_failures_outside_window(h: Harness) -> None:
    h.mgr.fail["freeze"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "timeout")

    async def main() -> None:
        for i in range(3):
            if i:
                await h.clock.advance(301)
            await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        # failures 301 s apart: by the third, the first has left the 600 s window
        assert h.ex.breaker_state() == {"open": False, "until": None, "failures": 2}
        await h.clock.advance(601)
        assert h.ex.breaker_state()["failures"] == 0

    run(main)


def test_known_no_effect_errors_skip_breaker(h: Harness) -> None:
    async def main() -> None:
        for name in ("org.freedesktop.systemd1.UnitInactive", "org.sentry-v2.Closed"):
            h.mgr.fail["freeze"] = SystemdError(name, "x")
            [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
            assert rec.status == "failed" and name in (rec.error or "")
        assert h.ex.breaker_state()["failures"] == 0
        assert h.ex.active() == []

    run(main)
    assert "thaw" not in [c[0] for c in h.mgr.calls]


@pytest.mark.parametrize(
    "name",
    [
        "org.freedesktop.DBus.Error.AccessDenied",
        "org.freedesktop.DBus.Error.InvalidArgs",
        "org.freedesktop.systemd1.UnitMasked",
    ],
)
def test_refused_throttle_is_not_compensated(h: Harness, name: str) -> None:
    h.mgr.fail["set_properties"] = SystemdError(name, "no")

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, None, 60))])
        assert rec.status == "failed" and name in (rec.error or "")
        await settle()
        assert h.ex.active() == []
        assert h.ex.breaker_state()["failures"] == 0

    run(main)
    assert [c[0] for c in h.mgr.calls].count("set_properties") == 1


def test_pause_forces_dry_run(h: Harness) -> None:
    async def main() -> None:
        h.ex.pause()
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert rec.status == "dry_run"
        h.ex.resume()
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert rec.status == "applied"
        await h.ex.shutdown()

    run(main)


def test_shutdown_rolls_back_two_active(h: Harness) -> None:
    async def main() -> None:
        await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, 5, 600))])
        await h.ex.handle(psi_incident("system.slice/batch-2.service"), [(policy(), Freeze(600))])
        assert len(h.ex.active()) == 2
        await h.ex.shutdown()
        assert h.ex.active() == []

    run(main)
    assert h.mgr.units[UNIT].cpu_weight == UNSET
    assert h.mgr.units["batch-2.service"].freezer_state == "running"
    assert sorted(s for a, s in h.statuses() if s == "rolled_back") == ["rolled_back"] * 2


def test_manual_rollback_by_id(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(600))])
        assert await h.ex.rollback("nope") == []
        [done] = await h.ex.rollback(rec.id)
        assert done.status == "rolled_back"
        await h.clock.advance(700)

    run(main)
    assert [c[0] for c in h.mgr.calls].count("thaw") == 1


def test_limits(fake_cgroupfs: Path) -> None:
    h = Harness(fake_cgroupfs, max_active_actions=2, max_concurrent_freezes=1)

    async def main() -> None:
        recs = await h.ex.handle(
            psi_incident(), [(policy(), Freeze(60)), (policy(), Throttle(64 * MiB, None, 60))]
        )
        assert [r.status for r in recs] == ["applied", "applied"]
        recs = await h.ex.handle(
            psi_incident("system.slice/batch-2.service"),
            [(policy(), Freeze(60)), (policy(), Throttle(64 * MiB, None, 60))],
        )
        assert [(r.status, r.error) for r in recs] == [("failed", "limit")] * 2
        assert h.ex.breaker_state()["failures"] == 0
        await h.ex.shutdown()

    run(main)


def test_second_throttle_on_same_unit_refused(h: Harness) -> None:
    async def main() -> None:
        plan = [(policy(), Throttle(64 * MiB, None, 60))]
        await h.ex.handle(psi_incident(), plan)
        [rec] = await h.ex.handle(psi_incident(), plan)
        assert (rec.status, rec.error) == ("failed", "already active")
        await h.ex.shutdown()

    run(main)


def test_freeze_on_frozen_unit_refused(h: Harness) -> None:
    h.mgr.units[UNIT] = dataclasses.replace(h.mgr.units[UNIT], freezer_state="frozen")

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert (rec.status, rec.error) == ("failed", "already frozen")

    run(main)


def test_unit_missing_at_prepare(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(
            psi_incident("system.slice/ghost.service"), [(policy(), Freeze(60))]
        )
        assert (rec.status, rec.error) == ("failed", "unit not found")

    run(main)


def set_pressure(path: Path, avg10: float) -> None:
    path.write_text(PRESSURE.format(k="some", a=avg10) + PRESSURE.format(k="full", a=0))


def test_freeze_thaws_early_when_parent_pressure_drops(h: Harness, fake_cgroupfs: Path) -> None:
    parent = fake_cgroupfs / "cgroup" / "system.slice" / "memory.pressure"
    set_pressure(parent, 42)

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(600))])
        # the frozen child itself reads calm; the parent is what the freeze relieves
        set_pressure(fake_cgroupfs / "cgroup" / CG / "memory.pressure", 0)
        await h.clock.advance(5)
        assert h.mgr.units[UNIT].freezer_state == "frozen"
        # release_below defaults to half of 150ms/1s = 7.5%
        set_pressure(parent, 7.4)
        await h.clock.advance(5)
        assert h.mgr.units[UNIT].freezer_state == "running"
        assert h.journal.load()[rec.id].status == "rolled_back"

    run(main)


def test_freeze_explicit_release_below_and_unreadable_pressure(
    h: Harness, fake_cgroupfs: Path
) -> None:
    pressure = fake_cgroupfs / "cgroup" / "system.slice" / "memory.pressure"

    async def main() -> None:
        await h.ex.handle(psi_incident(), [(policy(), Freeze(600, release_below=50))])
        assert not pressure.exists()  # unreadable: treated as still high
        await h.clock.advance(5)
        assert h.mgr.units[UNIT].freezer_state == "frozen"
        set_pressure(pressure, 42)
        await h.clock.advance(5)
        assert h.mgr.units[UNIT].freezer_state == "running"

    run(main)


def test_top_level_unit_watches_system_pressure(h: Harness, fake_cgroupfs: Path) -> None:
    h.mgr.units["top.service"] = dataclasses.replace(NGINX, cgroup="top.service")
    system = fake_cgroupfs / "proc" / "pressure" / "memory"
    set_pressure(system, 42)

    async def main() -> None:
        await h.ex.handle(psi_incident("top.service"), [(policy(), Freeze(600))])
        await h.clock.advance(5)
        assert h.mgr.units["top.service"].freezer_state == "frozen"
        set_pressure(system, 1)
        await h.clock.advance(5)
        assert h.mgr.units["top.service"].freezer_state == "running"

    run(main)


def test_backup_reload_applied_not_active(h: Harness, fake_cgroupfs: Path) -> None:
    frag = fake_cgroupfs / "batch-1.service"
    frag.write_text("[Service]\n")
    h.mgr.units[UNIT] = dataclasses.replace(h.mgr.units[UNIT], fragment_path=str(frag))

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), BackupReload())])
        assert (rec.status, rec.expires_at) == ("applied", None)
        assert rec.backup_id and rec.backup_id.startswith(f"{UNIT}/")
        assert h.ex.active() == []
        h.mgr.reloadable[UNIT] = False
        await h.clock.advance(1)
        [rec] = await h.ex.handle(psi_incident(), [(policy(), BackupReload())])
        assert (rec.status, rec.error) == ("failed", "unit has no ExecReload")
        assert rec.backup_id is not None
        assert (h.ex.backups_dir / rec.backup_id / "MANIFEST.sha256").exists()
        assert h.ex.breaker_state()["failures"] == 0

    run(main)


def test_backup_failure_is_recorded(h: Harness) -> None:
    h.mgr.units[UNIT] = dataclasses.replace(h.mgr.units[UNIT], fragment_path="/nonexistent/x")

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), BackupReload())])
        assert rec.status == "failed" and "nonexistent" in (rec.error or "")

    run(main)
    assert [c[0] for c in h.mgr.calls] == ["get_properties"]


def test_unit_gone_between_prepare_and_apply(h: Harness) -> None:
    h.mgr.fail["freeze"] = UnitNotFound(UNIT)

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert (rec.status, rec.error) == ("failed", "unit not found")
        assert h.ex.breaker_state()["failures"] == 0

    run(main)


def test_unit_failed_incident_targets_unit(h: Harness) -> None:
    ev = UnitEvent(ts_us=1, unit=UNIT, kind="failed", result="exit-code")
    inc = Incident("inc-3", "unit_failed", 1, UNIT, ev, (), ())

    async def main() -> None:
        [rec] = await h.ex.handle(inc, [(policy(when=UnitFailedWhen((UNIT,))), Freeze(60))])
        assert (rec.status, rec.target) == ("applied", UNIT)
        await h.ex.shutdown()

    run(main)


def test_prepare_failures(h: Harness, fake_cgroupfs: Path) -> None:
    (fake_cgroupfs / "cgroup" / CG / "memory.current").unlink()

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(Percent(50), None, 60))])
        assert rec.status == "failed" and "memory.current" in (rec.error or "")
        assert h.ex.breaker_state()["failures"] == 0
        h.mgr.fail["get_properties"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "x")
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert rec.status == "failed" and "NoReply" in (rec.error or "")
        assert h.ex.breaker_state()["failures"] == 1

    run(main)


def test_ambiguous_apply_failure_is_compensated(h: Harness) -> None:
    real = h.mgr.freeze

    async def took_effect_then_failed(unit: str) -> None:
        await real(unit)
        raise SystemdError("org.freedesktop.DBus.Error.NoReply", "timeout")

    h.mgr.freeze = took_effect_then_failed  # type: ignore[method-assign]

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert rec.status == "planned"
        await settle()
        final = h.journal.load()[rec.id]
        assert final.status == "rolled_back"
        assert final.error == "apply outcome unknown: org.freedesktop.DBus.Error.NoReply"

    run(main)
    assert h.mgr.units[UNIT].freezer_state == "running"
    assert [c[0] for c in h.mgr.calls].count("thaw") == 1


def test_unexpected_error_compensated_and_plan_continues(h: Harness) -> None:
    h.mgr.fail["set_properties"] = RuntimeError("boom")
    pol = policy(Throttle(64 * MiB, None, 60), Notify())

    async def main() -> None:
        recs = await h.ex.handle(psi_incident(), [(pol, a) for a in pol.actions])
        assert [r.status for r in recs] == ["planned", "applied"]
        assert len(h.notified) == 1
        del h.mgr.fail["set_properties"]
        await settle()
        final = h.journal.load()[recs[0].id]
        # set_properties never took effect, so the values differ from what was written
        assert (final.status, final.error) == (
            "rolled_back",
            "apply outcome unknown: RuntimeError; changed since; left as is",
        )

    run(main)


def test_journal_failure_before_apply_touches_nothing(h: Harness) -> None:
    real = h.journal.append

    def broken(rec: ActionRecord) -> None:
        if rec.status == "planned":
            raise OSError("disk full")
        real(rec)

    h.journal.append = broken  # type: ignore[method-assign]

    async def main() -> None:
        recs = await h.ex.handle(psi_incident(), [(policy(), Freeze(60)), (policy(), Notify())])
        assert [(r.status, r.error) for r in recs] == [
            ("failed", "internal error: disk full"),
            ("applied", None),
        ]

    run(main)
    assert [c[0] for c in h.mgr.calls] == ["get_properties"]


def test_cancelled_mid_apply_compensates_and_notifies(h: Harness) -> None:
    gate = asyncio.Event()
    real = h.mgr.freeze

    async def slow(unit: str) -> None:
        await real(unit)
        await gate.wait()

    h.mgr.freeze = slow  # type: ignore[method-assign]

    async def main() -> None:
        task = asyncio.create_task(h.ex.handle(psi_incident(), [(policy(), Freeze(60))]))
        await settle()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await settle()
        assert h.notified == [(psi_incident(), [])]  # cut off before the record was returned
        assert h.mgr.units[UNIT].freezer_state == "running"
        [final] = h.journal.load().values()
        assert (final.status, final.error) == (
            "rolled_back",
            "apply outcome unknown: CancelledError",
        )

    run(main)


def test_shutdown_during_apply_rolls_back_and_refuses_new(h: Harness) -> None:
    gate = asyncio.Event()
    real = h.mgr.freeze

    async def slow(unit: str) -> None:
        await gate.wait()
        await real(unit)

    h.mgr.freeze = slow  # type: ignore[method-assign]

    async def main() -> None:
        handling = asyncio.create_task(h.ex.handle(psi_incident(), [(policy(), Freeze(600))]))
        await settle()
        stopping = asyncio.create_task(h.ex.shutdown())
        await settle()
        assert not stopping.done()  # waits for the in-flight apply
        gate.set()
        [rec] = await handling
        await stopping
        assert h.journal.load()[rec.id].status == "rolled_back"
        [late] = await h.ex.handle(
            psi_incident("system.slice/batch-2.service"), [(policy(), Freeze(600))]
        )
        assert (late.status, late.error) == ("failed", "shutting down")

    run(main)
    assert h.mgr.units[UNIT].freezer_state == "running"
    assert ("freeze", "batch-2.service") not in h.mgr.calls


def test_stuck_target_refused_until_manual_rollback(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        h.mgr.fail["thaw"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "x")
        await h.clock.advance(60 + 243)
        assert h.journal.load()[rec.id].status == "rollback_failed"
        [again] = await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, None, 60))])
        assert (again.status, again.error) == ("failed", "rollback pending")
        del h.mgr.fail["thaw"]
        [done] = await h.ex.rollback(rec.id)
        assert done.status == "rolled_back"
        [ok] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        assert ok.status == "applied"
        await h.ex.shutdown()

    run(main)


def test_replay_leaves_rollback_failed_to_operator(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    h.clock.now = 0
    h.journal.append(stored(id="s1", action="freeze", status="rollback_failed"))
    h.clock.now = 30 * 86400

    async def main() -> None:
        await asyncio.wait_for(h.ex.replay(), 1)  # no retry loop
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, None, 60))])
        assert (rec.status, rec.error) == ("failed", "rollback pending")

    run(main)
    assert [c for c in h.mgr.calls if c[0] == "thaw"] == []
    assert h.journal.load()["s1"].status == "rollback_failed"  # survives compaction
    assert caplog.text.count("s1") == 1


def test_manual_retry_waits_as_planned(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Freeze(60))])
        h.mgr.fail["thaw"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "x")
        await h.clock.advance(60 + 243)
        retry = asyncio.create_task(h.ex.rollback(rec.id))
        await settle()
        assert [r.status for r in h.ex.active()] == ["planned"]
        retry.cancel()

    run(main)


def test_throttle_left_alone_if_changed_since(h: Harness, caplog: pytest.LogCaptureFixture) -> None:
    rec_id: list[str] = []

    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(Percent(50), 30, 60))])
        rec_id.append(rec.id)
        assert rec.params == {"memory_high": 32 * MiB, "cpu_weight": 30}  # resolved, floored
        # an operator raises the limit by hand while the throttle is active
        h.mgr.units[UNIT] = dataclasses.replace(h.mgr.units[UNIT], memory_high=8 * 1024 * MiB)
        await h.clock.advance(60)
        final = h.journal.load()[rec.id]
        assert (final.status, final.error) == ("rolled_back", "changed since; left as is")

    run(main)
    assert [c[0] for c in h.mgr.calls].count("set_properties") == 1
    assert h.mgr.units[UNIT].memory_high == 8 * 1024 * MiB
    [warning] = [r for r in caplog.records if "changed since" in r.getMessage()]
    assert warning.levelname == "WARNING"
    assert UNIT in warning.getMessage() and rec_id[0] in warning.getMessage()


def test_dry_run_reports_limit(fake_cgroupfs: Path) -> None:
    h = Harness(fake_cgroupfs, max_active_actions=1)

    async def main() -> None:
        await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, None, 60))])
        [rec] = await h.ex.handle(
            psi_incident("system.slice/batch-2.service"), [(policy(mode="dry-run"), Freeze(60))]
        )
        assert (rec.status, rec.error) == ("failed", "limit")
        await h.ex.shutdown()

    run(main)


def test_monotonic_deadline_bounds_wall_clock_jump(h: Harness) -> None:
    async def main() -> None:
        [rec] = await h.ex.handle(psi_incident(), [(policy(), Throttle(64 * MiB, None, 60))])
        h.clock.now -= 3600  # wall clock steps back an hour
        await h.clock.advance(60)
        assert h.journal.load()[rec.id].status == "rolled_back"

    run(main)
