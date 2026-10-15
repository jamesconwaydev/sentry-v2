"""Decides whether, how and for how long each planned action runs.

Ordering guarantees: one lock serialises every journal write and D-Bus call
(handle, rollback, replay), and an enforced action is journalled `planned`
with its previous values before systemd is touched. Rollback retries sleep
outside the lock.

A throttle or freeze whose apply call fails in a way that may still have
taken effect (a timeout, a dropped bus, an unexpected exception or a
cancellation) is never just marked failed: it stays active as `planned`
and is rolled back straight away, since restore and thaw are idempotent.

Worst-case rollback time: one record makes 10 attempts with 243 s of
backoff in total (1+2+4+8+16+32+60+60+60) plus up to 10 D-Bus timeouts of
10 s each, so about 343 s. Records retry concurrently, but D-Bus calls are
serialised by the lock, so N records that all time out take at most
243 s + N * 100 s. Shutdown can take that long; the unit's TimeoutStopSec
must allow for it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from . import actions
from .cgroupfs import CgroupFS
from .config_types import LimitsConfig, ProtectionConfig
from .events import Incident
from .ids import uuid7
from .policy import (
    ActionSpec,
    BackupReload,
    Freeze,
    Mode,
    Notify,
    Policy,
    PsiWhen,
    Throttle,
    effective_mode,
    is_protected,
)
from .state import REVERSIBLE, ActionJournal, ActionKind, ActionRecord, Status
from .systemd import SystemdError, SystemdManager, UnitNotFound

log = logging.getLogger(__name__)

SinksNotify = Callable[[Incident, list[ActionRecord]], Awaitable[None]]
Alert = Callable[[str, dict[str, Any]], Awaitable[None]]
Watch = tuple[str, str, float]  # (cgroup, resource, release_below)

_KIND: dict[type, ActionKind] = {
    Throttle: "throttle",
    Freeze: "freeze",
    BackupReload: "backup_reload",
    Notify: "notify",
}
POLL = 5.0  # seconds between freeze pressure checks
ROLLBACK_ATTEMPTS = 10
ROLLBACK_MAX_DELAY = 60.0
COMPACT_AFTER = 7 * 86400.0
NO_RELOAD = "org.freedesktop.systemd1.JobTypeNotApplicable"
# D-Bus errors raised before systemd changed anything; they do not trip the breaker
NO_EFFECT = frozenset(
    {
        actions.UNIT_INACTIVE,
        NO_RELOAD,
        "org.freedesktop.DBus.Error.AccessDenied",
        "org.freedesktop.DBus.Error.InvalidArgs",
        "org.freedesktop.systemd1.UnitMasked",
        "org.sentry-v2.UnsupportedUnitType",
        "org.sentry-v2.Closed",
    }
)


class Executor:
    """Applies planned actions, times them out and rolls them back.

    `clock` is wall time (it is persisted in `expires_at`); `monotonic`
    bounds the same expiry against wall-clock steps. `sleep` is injectable
    so tests drive time by hand. `mode` is the daemon's master switch and
    may be changed on reload.
    """

    def __init__(
        self,
        mgr: SystemdManager,
        fs: CgroupFS,
        journal: ActionJournal,
        limits: LimitsConfig,
        protection: ProtectionConfig,
        sinks_notify: SinksNotify,
        alert: Alert,
        clock: Callable[[], float],
        backups_dir: Path,
        *,
        daemon_mode: Mode = "dry-run",
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.mgr = mgr
        self.fs = fs
        self.journal = journal
        self.limits = limits
        self.protection = protection
        self.backups_dir = backups_dir
        self.mode: Mode = daemon_mode
        self._notify = sinks_notify
        self._alert = alert
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic
        self._lock = asyncio.Lock()
        self._active: dict[str, ActionRecord] = {}  # awaiting rollback
        self._failed: dict[str, ActionRecord] = {}  # rollback_failed; their targets are stuck
        self._timers: dict[str, asyncio.Task[Any]] = {}
        self._paused = False
        self._closing = False
        self._failures: deque[float] = deque()
        self._open_until: float | None = None
        self._pending_alerts: list[tuple[str, dict[str, Any]]] = []

    # -- control -----------------------------------------------------------

    def pause(self) -> None:
        """Force dry-run for new actions. Active actions keep their timers."""
        self._paused = True

    def resume(self) -> None:
        """Undo `pause()`."""
        self._paused = False

    def active(self) -> list[ActionRecord]:
        """Throttles and freezes awaiting rollback (applied, or of unknown outcome)."""
        return list(self._active.values())

    def breaker_state(self) -> dict[str, Any]:
        """{"open", "until", "failures"}: whether apply failures have forced dry-run."""
        now = self._clock()
        self._prune(now)
        is_open = self._open_until is not None and now < self._open_until
        return {
            "open": is_open,
            "until": self._open_until if is_open else None,
            "failures": len(self._failures),
        }

    # -- handling incidents ------------------------------------------------

    async def handle(
        self, incident: Incident, plan: list[tuple[Policy, ActionSpec]]
    ) -> list[ActionRecord]:
        """Run each planned action in order, then hand the records to the sinks once.

        A failed action never stops the ones after it, and the sinks are
        called even if this is cancelled part-way.
        """
        records: list[ActionRecord] = []
        try:
            async with self._lock:
                for policy, spec in plan:
                    records.append(await self._guarded(incident, policy, spec))
        finally:
            await self._flush_alerts()
            await self._notify(incident, records)
        return records

    def _mode_for(self, policy: Policy) -> Mode:
        if self._paused or self.breaker_state()["open"]:
            return "dry-run"
        return effective_mode(self.mode, policy.mode)

    def _target_unit(self, incident: Incident) -> str | None:
        match incident.kind:
            case "unit_failed":
                return incident.target
            case "psi":
                return self.fs.unit_of(incident.target)
            case _:
                return None

    async def _guarded(self, incident: Incident, policy: Policy, spec: ActionSpec) -> ActionRecord:
        unit = self._target_unit(incident)
        rec = ActionRecord(
            id=uuid7(), policy=policy.name, action=_KIND[type(spec)],
            target=unit or incident.target, mode=self._mode_for(policy), status="planned",
            previous={}, applied_at=None, expires_at=None, error=None,
            incident_id=incident.id, configured_mode=policy.mode,
        )  # fmt: skip
        try:
            return await self._run(rec, unit, policy, spec)
        except Exception as e:
            # _run handles everything after the D-Bus call itself, so reaching
            # here means nothing was applied (e.g. the planned write failed)
            log.exception("%s %s on %s: internal error", policy.name, rec.action, rec.target)
            failed = dataclasses.replace(rec, status="failed", error=f"internal error: {e}")
            try:
                self.journal.append(failed)
            except Exception:
                log.exception("cannot journal failed record %s", rec.id)
            return failed

    def _finish(
        self, rec: ActionRecord, status: Status, error: str | None = None, **kw: Any
    ) -> ActionRecord:
        final = dataclasses.replace(rec, status=status, error=error, **kw)
        self.journal.append(final)
        if error:
            log.warning("%s %s on %s: %s", rec.policy, rec.action, rec.target, error)
        return final

    async def _run(
        self, rec: ActionRecord, unit: str | None, policy: Policy, spec: ActionSpec
    ) -> ActionRecord:
        if self._closing:
            return self._finish(rec, "failed", "shutting down")
        if isinstance(spec, Notify):
            return self._finish(rec, "dry_run" if rec.mode == "dry-run" else "applied")
        if unit is None:
            return self._finish(rec, "failed", "no unit target")
        if is_protected(unit, self.protection.protected):
            return self._finish(rec, "failed", "protected")
        if refusal := self._check_limits(rec.action, unit):
            return self._finish(rec, "failed", refusal)
        if rec.mode == "dry-run":
            return self._finish(rec, "dry_run", params=actions.describe(spec))

        try:
            previous, params = await actions.prepare(spec, unit, self.mgr, self.fs)
        except actions.Refused as e:
            return self._finish(rec, "failed", str(e))
        except UnitNotFound:
            return self._finish(rec, "failed", "unit not found")
        except SystemdError as e:
            if e.name not in NO_EFFECT:
                self._apply_failed()
            return self._finish(rec, "failed", str(e))
        except OSError as e:
            return self._finish(rec, "failed", str(e))

        rec = dataclasses.replace(rec, previous=previous, params=params)
        self.journal.append(rec)
        try:
            if isinstance(spec, BackupReload):
                backup_id = actions.backup(unit, params["files"], self.backups_dir, self._clock())
                rec = dataclasses.replace(rec, backup_id=backup_id)
            await actions.apply(spec, unit, params, self.mgr)
            now = self._clock()
            if not isinstance(spec, Throttle | Freeze):
                return self._finish(rec, "applied", applied_at=now)
            duration = min(spec.duration, self.limits.max_action_duration)
            applied = self._finish(rec, "applied", applied_at=now, expires_at=now + duration)
            self._active[rec.id] = applied
            watch = self._watch_for(policy, spec, params) if isinstance(spec, Freeze) else None
            deadline = self._monotonic() + duration
            self._timers[rec.id] = asyncio.create_task(self._expire(applied, watch, deadline))
            return applied
        except BaseException as e:
            return self._apply_error(rec, e)

    def _apply_error(self, rec: ActionRecord, e: BaseException) -> ActionRecord:
        """Record a failure after `planned`; compensate when it may have taken effect.

        Re-raises anything that is not an Exception (cancellation, exit).
        """
        name = e.name if isinstance(e, SystemdError) else type(e).__name__
        if isinstance(e, UnitNotFound):
            return self._finish(rec, "failed", "unit not found")
        if name == NO_RELOAD:
            return self._finish(rec, "failed", "unit has no ExecReload")
        if name in NO_EFFECT:
            return self._finish(rec, "failed", str(e))
        if isinstance(e, SystemdError):
            self._apply_failed()
        if rec.action in REVERSIBLE:
            final = dataclasses.replace(rec, error=f"apply outcome unknown: {name}")
            self._active[rec.id] = final
            self._timers[rec.id] = asyncio.create_task(self._rollback_record(rec.id))
            log.error("%s on %s: %s; rolling back", rec.action, rec.target, final.error)
            try:
                self.journal.append(final)
            except Exception:
                log.exception("cannot journal %s", rec.id)
        else:  # a backup or reload: nothing automatic to undo
            final = self._finish(rec, "failed", str(e) or name)
        if not isinstance(e, Exception):
            raise e
        return final

    def _check_limits(self, kind: ActionKind, unit: str) -> str | None:
        if kind not in REVERSIBLE:
            return None
        if any(r.target == unit for r in self._failed.values()):
            return "rollback pending"
        active = self.active()
        if any(r.target == unit and r.action == kind for r in active):
            # a second capture would record the first action's values as "previous"
            return "already active"
        if len(active) >= self.limits.max_active_actions:
            return "limit"
        if kind == "freeze":
            freezes = sum(r.action == "freeze" for r in active)
            if freezes >= self.limits.max_concurrent_freezes:
                return "limit"
        return None

    def _prune(self, now: float) -> None:
        while self._failures and self._failures[0] < now - self.limits.breaker_window:
            self._failures.popleft()

    def _apply_failed(self) -> None:
        """Count a systemd failure; trip the breaker at the configured threshold."""
        now = self._clock()
        self._failures.append(now)
        self._prune(now)
        if len(self._failures) >= self.limits.breaker_failures:
            self._open_until = now + self.limits.breaker_cooldown
            log.error("circuit breaker open until %s: forcing dry-run", self._open_until)
            self._pending_alerts.append(
                ("breaker_open", {"failures": len(self._failures), "until": self._open_until})
            )
            self._failures.clear()

    async def _flush_alerts(self) -> None:
        pending, self._pending_alerts = self._pending_alerts, []
        for kind, detail in pending:
            await self._alert(kind, detail)

    # -- expiry and rollback -----------------------------------------------

    def _watch_for(self, policy: Policy, spec: Freeze, params: dict[str, Any]) -> Watch | None:
        """What early thaw watches, or None for expiry only.

        The watcher reads the frozen unit's parent cgroup: that is the
        pressure the freeze relieves, while the frozen child itself reads
        calm. A unit directly under the root reads system-wide
        /proc/pressure instead.
        """
        when = policy.when
        if not isinstance(when, PsiWhen):
            return None
        release = spec.release_below
        if release is None:
            release = when.stall_us / when.window_us * 100 / 2
        cgroup: str = params["cgroup"]
        parent = cgroup.rsplit("/", 1)[0] if "/" in cgroup else ""
        return parent, when.resource, release

    async def _expire(self, rec: ActionRecord, watch: Watch | None, deadline: float) -> None:
        """Roll back at `expires_at` or the monotonic `deadline`, whichever comes first."""
        assert rec.expires_at is not None  # noqa: S101 - set for every timed action
        while (left := min(rec.expires_at - self._clock(), deadline - self._monotonic())) > 0:
            await self._sleep(min(left, POLL) if watch else left)
            if watch and self._pressure(watch[0], watch[1]) < watch[2]:
                log.info("%s on %s: pressure released, thawing early", rec.action, rec.target)
                break
        await self._rollback_record(rec.id)

    def _pressure(self, cgroup: str, resource: str) -> float:
        try:
            if not cgroup:
                return self.fs.read_system_pressure(resource)["some"].avg10
            return self.fs.read_pressure(cgroup, resource)["some"].avg10
        except (OSError, KeyError, ValueError) as e:
            log.warning("%s: cannot read %s pressure: %s", cgroup or "/", resource, e)
            return float("inf")

    async def _rollback_record(self, rec_id: str) -> ActionRecord | None:
        """Undo one active record, retrying with backoff; alert if it never succeeds."""
        error = ""
        for attempt in range(ROLLBACK_ATTEMPTS):
            if attempt:
                await self._sleep(min(2.0 ** (attempt - 1), ROLLBACK_MAX_DELAY))
            async with self._lock:
                rec = self._active.get(rec_id)
                if rec is None:
                    return None  # someone else closed it
                try:
                    note = await actions.rollback(rec, self.mgr)
                except Exception as e:  # any failure is retried; the last one is recorded
                    error = str(e)
                    log.warning("rollback %s attempt %d failed: %s", rec_id, attempt + 1, e)
                    continue
                if note == actions.CHANGED_SINCE:
                    log.warning(
                        "rollback %s on %s: %s (changed by someone else)", rec_id, rec.target, note
                    )
                return self._close(
                    rec, "rolled_back", "; ".join(e for e in (rec.error, note) if e) or None
                )
        async with self._lock:
            rec = self._active.get(rec_id)
            if rec is None:  # pragma: no cover - closed while we slept
                return None
            final = self._close(rec, "rollback_failed", error)
        log.critical("giving up on rolling back %s %s: %s", rec.action, rec.target, error)
        await self._alert("rollback_failed", {"record": dataclasses.asdict(final)})
        return final

    def _close(self, rec: ActionRecord, status: Status, error: str | None) -> ActionRecord:
        final = dataclasses.replace(rec, status=status, error=error)
        try:
            self.journal.append(final)
        except Exception:  # replay will roll it back again, which is harmless
            log.exception("cannot journal %s as %s", rec.id, status)
        del self._active[rec.id]
        if status == "rollback_failed":
            self._failed[rec.id] = final
        else:
            self._failed.pop(rec.id, None)
        task = self._timers.pop(rec.id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        return final

    async def rollback(self, rec_id: str | None = None) -> list[ActionRecord]:
        """Roll back one action by id, or every active one; returns the closed records.

        An id whose rollback already failed is retried (waiting as `planned`);
        success clears its target for new actions.
        """
        if rec_id is not None and rec_id in self._failed:
            retry = dataclasses.replace(self._failed[rec_id], status="planned", error=None)
            self._active[rec_id] = retry
        return await self._rollback_ids(list(self._active) if rec_id is None else [rec_id])

    async def _rollback_ids(self, ids: list[str]) -> list[ActionRecord]:
        for i in ids:
            task = self._timers.pop(i, None)
            if task is not None:
                task.cancel()
        done = await asyncio.gather(*(self._rollback_record(i) for i in ids))
        return [r for r in done if r is not None]

    async def shutdown(self) -> None:
        """SIGTERM: refuse new actions, wait for any in-flight apply, roll back all active."""
        async with self._lock:
            self._closing = True
            ids = list(self._active)
        await self._rollback_ids(ids)

    async def replay(self) -> None:
        """Startup: undo whatever an earlier run left open, then compact.

        Rollbacks that already failed are not retried here: their targets
        stay stuck until an operator runs `rollback(id)`.
        """
        async with self._lock:
            for rec in self.journal.load().values():
                if rec.status == "rollback_failed":
                    log.warning(
                        "%s %s on %s: earlier rollback failed; refusing new actions on it "
                        "until it is rolled back by hand",
                        rec.id, rec.action, rec.target,
                    )  # fmt: skip
                    self._failed[rec.id] = rec
                elif not rec.is_open:
                    continue
                elif rec.action in REVERSIBLE:
                    self._active[rec.id] = rec
                else:  # a reload or backup cut short; nothing to undo
                    cut = dataclasses.replace(rec, status="failed", error="interrupted")
                    self.journal.append(cut)
        await self.rollback(None)
        async with self._lock:
            self.journal.compact(COMPACT_AFTER, self._clock())
