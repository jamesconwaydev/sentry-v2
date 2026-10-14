"""Decides whether, how and for how long each planned action runs.

Ordering guarantees: one lock serialises every journal write and D-Bus call
(handle, rollback, replay), and an enforced action is journalled `planned`
with its previous values before systemd is touched. Rollback retries sleep
outside the lock.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
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
from .state import ActionJournal, ActionKind, ActionRecord, Status
from .systemd import SystemdError, SystemdManager, UnitNotFound

log = logging.getLogger(__name__)

SinksNotify = Callable[[Incident, list[ActionRecord]], Awaitable[None]]
Alert = Callable[[str, dict[str, Any]], Awaitable[None]]

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


class Executor:
    """Applies planned actions, times them out and rolls them back.

    `clock` is wall time (it is persisted in `expires_at`); `sleep` is
    injectable so tests drive time by hand. `mode` is the daemon's master
    switch and may be changed on reload.
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
        self._lock = asyncio.Lock()
        self._active: dict[str, ActionRecord] = {}
        self._timers: dict[str, asyncio.Task[None]] = {}
        self._paused = False
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
        """Applied throttles and freezes awaiting rollback."""
        return [r for r in self._active.values() if r.status == "applied"]

    def breaker_state(self) -> dict[str, Any]:
        """{"open", "until", "failures"}: whether apply failures have forced dry-run."""
        is_open = self._open_until is not None and self._clock() < self._open_until
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

        A failed action never stops the ones after it.
        """
        async with self._lock:
            records = [await self._run(incident, policy, spec) for policy, spec in plan]
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

    async def _run(self, incident: Incident, policy: Policy, spec: ActionSpec) -> ActionRecord:
        kind = _KIND[type(spec)]
        mode = self._mode_for(policy)
        unit = self._target_unit(incident)
        rec = ActionRecord(
            id=uuid7(), policy=policy.name, action=kind, target=unit or incident.target,
            mode=mode, status="planned", previous={}, applied_at=None, expires_at=None,
            error=None, incident_id=incident.id, configured_mode=policy.mode,
        )  # fmt: skip

        def done(status: Status, error: str | None = None, **kw: Any) -> ActionRecord:
            final = dataclasses.replace(rec, status=status, error=error, **kw)
            self.journal.append(final)
            if error:
                log.warning("%s %s on %s: %s", policy.name, kind, rec.target, error)
            return final

        if isinstance(spec, Notify):
            return done("dry_run" if mode == "dry-run" else "applied")
        if unit is None:
            return done("failed", "no unit target")
        if is_protected(unit, self.protection.protected):
            return done("failed", "protected")
        if mode == "dry-run":
            return done("dry_run")
        if refusal := self._check_limits(kind, unit):
            return done("failed", refusal)

        try:
            previous, params = await actions.prepare(spec, unit, self.mgr, self.fs)
        except actions.Refused as e:
            return done("failed", str(e))
        except UnitNotFound:
            return done("failed", "unit not found")
        except SystemdError as e:
            self._apply_failed()
            return done("failed", str(e))
        except OSError as e:
            return done("failed", str(e))

        rec = dataclasses.replace(rec, previous=previous, params=params)
        self.journal.append(rec)
        try:
            if isinstance(spec, BackupReload):
                backup_id = actions.backup(unit, params["files"], self.backups_dir, self._clock())
                rec = dataclasses.replace(rec, backup_id=backup_id)
            await actions.apply(spec, unit, params, self.mgr)
        except UnitNotFound:
            return done("failed", "unit not found")
        except SystemdError as e:
            if e.name == NO_RELOAD:
                return done("failed", "unit has no ExecReload")
            self._apply_failed()
            return done("failed", str(e))
        except OSError as e:
            return done("failed", str(e))

        now = self._clock()
        if not isinstance(spec, Throttle | Freeze):
            return done("applied", applied_at=now)
        duration = min(spec.duration, self.limits.max_action_duration)
        rec = done("applied", applied_at=now, expires_at=now + duration)
        self._active[rec.id] = rec
        watch = self._watch_for(policy, spec, params) if isinstance(spec, Freeze) else None
        self._timers[rec.id] = asyncio.create_task(self._expire(rec, watch))
        return rec

    def _check_limits(self, kind: ActionKind, unit: str) -> str | None:
        if kind not in ("throttle", "freeze"):
            return None
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

    def _apply_failed(self) -> None:
        """Count a systemd failure; trip the breaker at the configured threshold."""
        now = self._clock()
        self._failures.append(now)
        while self._failures and self._failures[0] < now - self.limits.breaker_window:
            self._failures.popleft()
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

    def _watch_for(
        self, policy: Policy, spec: Freeze, params: dict[str, Any]
    ) -> tuple[str, str, float] | None:
        """(cgroup, resource, release_below) for early thaw, or None for expiry only."""
        when = policy.when
        if not isinstance(when, PsiWhen):
            return None
        release = spec.release_below
        if release is None:
            release = when.stall_us / when.window_us * 100 / 2
        return params["cgroup"], when.resource, release

    async def _expire(self, rec: ActionRecord, watch: tuple[str, str, float] | None) -> None:
        assert rec.expires_at is not None  # noqa: S101 - set for every timed action
        while (left := rec.expires_at - self._clock()) > 0:
            await self._sleep(min(left, POLL) if watch else left)
            if watch and self._pressure(watch[0], watch[1]) < watch[2]:
                log.info("%s on %s: pressure released, thawing early", rec.action, rec.target)
                break
        await self._rollback_record(rec.id)

    def _pressure(self, cgroup: str, resource: str) -> float:
        try:
            return self.fs.read_pressure(cgroup, resource)["some"].avg10
        except (OSError, KeyError, ValueError) as e:
            log.warning("%s: cannot read %s pressure: %s", cgroup, resource, e)
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
                return self._close(rec, "rolled_back", note)
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
        self.journal.append(final)
        del self._active[rec.id]
        task = self._timers.pop(rec.id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        return final

    async def rollback(self, rec_id: str | None = None) -> list[ActionRecord]:
        """Roll back one active action by id, or all of them; returns the closed records."""
        ids = list(self._active) if rec_id is None else [rec_id]
        for i in ids:
            task = self._timers.pop(i, None)
            if task is not None:
                task.cancel()
        done = await asyncio.gather(*(self._rollback_record(i) for i in ids))
        return [r for r in done if r is not None]

    async def shutdown(self) -> None:
        """Roll back everything still active (SIGTERM)."""
        await self.rollback(None)

    async def replay(self) -> None:
        """Startup: undo whatever a previous run left open, then compact the journal."""
        async with self._lock:
            for rec in self.journal.load().values():
                if not rec.is_open:
                    continue
                if rec.action in ("throttle", "freeze"):
                    self._active[rec.id] = rec
                else:  # a reload or backup cut short; nothing to undo
                    cut = dataclasses.replace(rec, status="failed", error="interrupted")
                    self.journal.append(cut)
        await self.rollback(None)
        async with self._lock:
            self.journal.compact(COMPACT_AFTER, self._clock())
