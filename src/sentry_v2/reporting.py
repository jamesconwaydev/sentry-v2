"""Incident reporting: turns incidents and alerts into bundles for the sinks.

Bundles are built in the background so the executor never waits on them.
Every context lookup is bounded, and at most one systemd lookup made on
behalf of reporting or correlation is in flight at a time, so an action
queues behind one lookup at most.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from .bundle import BundleContext, HostInfo, Redactor, build_alert_bundle, build_bundle
from .cgroupfs import CgroupFS
from .collectors.journal import ReaderLike, unit_tail
from .events import Incident
from .state import ActionRecord
from .systemd import SystemdManager, UnitProps

log = logging.getLogger(__name__)

LOOKUP_TIMEOUT = 2.5  # per context lookup when building a bundle
BUNDLE_BUILDERS = 4
UNIT_INFO_TTL = 60.0
JOURNAL_TAIL = 50
RESOURCES = ("memory", "cpu", "io")


class Reporter:
    """Builds bundles and hands each one to `submit`; caches unit properties.

    `redactor` may be replaced (on reload). `unit_info` is the correlator's
    synchronous view of the cache, which `refresh` fills in the background.
    """

    def __init__(
        self,
        fs: CgroupFS,
        mgr: SystemdManager,
        journal_reader_factory: Callable[[], ReaderLike],
        host: HostInfo,
        redactor: Redactor,
        submit: Callable[[dict[str, Any]], None],
    ) -> None:
        self.fs = fs
        self.mgr = mgr
        self.host = host
        self.redactor = redactor
        self._journal_factory = journal_reader_factory
        self._submit = submit
        # unit -> (monotonic fetch time, wall fetch time, props or None while in flight)
        self._units: dict[str, tuple[float, float, UnitProps | None]] = {}
        # held until the call really ends, so lookups never pile up on the D-Bus thread
        self._lookup_slot = asyncio.Semaphore(1)
        self._bundle_slots = asyncio.Semaphore(BUNDLE_BUILDERS)
        self._bundles: set[asyncio.Task[None]] = set()
        self._fetches: set[asyncio.Task[Any]] = set()

    def _spawn(self, coro: Coroutine[Any, Any, Any], name: str, into: set[Any]) -> None:
        task = asyncio.create_task(coro, name=name)
        into.add(task)
        task.add_done_callback(lambda t: self._done(t, into))

    @staticmethod
    def _done(task: asyncio.Task[Any], into: set[Any]) -> None:
        into.discard(task)
        if not task.cancelled() and (e := task.exception()) is not None:
            log.error("task %s failed", task.get_name(), exc_info=e)

    async def drain(self, timeout: float) -> None:
        """Shutdown: give bundles still being built `timeout` seconds, then cancel the rest."""
        late: set[asyncio.Task[Any]] = set(self._fetches)
        if self._bundles:
            _done, pending = await asyncio.wait(self._bundles, timeout=timeout)
            late |= pending
        for t in late:
            t.cancel()
        await asyncio.gather(*late, return_exceptions=True)

    # -- unit info -----------------------------------------------------------

    def unit_info(self, unit: str) -> tuple[set[str], str | None]:
        """Called synchronously by the correlator: whatever is cached right now."""
        props = self._units.get(unit, (0.0, 0.0, None))[2]
        return ({p.rsplit("/", 1)[-1] for p in props.exec_start} if props else set()), None

    def refresh(self, unit: str) -> None:
        """Fetch a unit's properties in the background unless they are fresh."""
        fetched, wall, props = self._units.get(unit, (float("-inf"), 0.0, None))
        if time.monotonic() - fetched < UNIT_INFO_TTL:
            return
        self._units[unit] = (time.monotonic(), wall, props)  # one fetch in flight per unit
        self._spawn(self._fetch_unit(unit), f"unit-info {unit}", self._fetches)

    def prune(self) -> None:
        stale = time.monotonic() - UNIT_INFO_TTL
        self._units = {u: e for u, e in self._units.items() if e[0] >= stale}

    async def _fetch_unit(self, unit: str) -> UnitProps | None:
        props = await self._lookup(unit)
        if props is not None:
            self._units[unit] = (time.monotonic(), time.time(), props)
        return props

    async def _lookup(self, unit: str) -> UnitProps | None:
        """get_properties within LOOKUP_TIMEOUT, or None. Never more than one in flight."""
        started = False

        async def call() -> UnitProps:
            nonlocal started
            async with self._lookup_slot:
                started = True
                return await self.mgr.get_properties(unit)

        # Shielded: a call that timed out keeps the slot until systemd answers.
        # One still waiting for the slot is dropped instead.
        task = asyncio.ensure_future(call())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        try:
            return await asyncio.wait_for(asyncio.shield(task), LOOKUP_TIMEOUT)
        except TimeoutError:
            log.warning("no properties for %s within %gs", unit, LOOKUP_TIMEOUT)
        except Exception as e:
            log.debug("no properties for %s: %r", unit, e)
        finally:  # timed out, failed or cancelled before the call began: drop it
            if not started:
                task.cancel()
        return None

    # -- bundles -------------------------------------------------------------

    async def sinks_notify(self, incident: Incident, records: list[ActionRecord]) -> None:
        """The executor's hook: build and send the bundle in the background."""
        rows = [dataclasses.asdict(r) for r in records]
        # ponytail: waiting builders are unbounded; an incident flood queues coroutines
        self._spawn(self._bundle(incident, rows), f"bundle {incident.id}", self._bundles)

    async def alert(self, kind: str, detail: dict[str, Any]) -> None:
        self._submit(build_alert_bundle(kind, detail, self.host))

    async def _bundle(self, incident: Incident, rows: list[dict[str, Any]]) -> None:
        async with self._bundle_slots:
            context = await self.context(incident)
            self._submit(build_bundle(incident, rows, context, self.host, self.redactor))

    async def context(self, incident: Incident) -> BundleContext:
        unit = None
        if incident.kind == "unit_failed":
            unit = incident.target
        elif incident.kind == "psi":
            unit = self.fs.unit_of(incident.target)
        props = None
        tail: list[dict[str, Any]] = []
        if unit is not None:
            _mono, wall, cached = self._units.get(unit, (0.0, 0.0, None))
            # a failure's props must postdate it (state, cgroup); PSI takes any fresh ones
            if incident.kind == "unit_failed" and wall * 1_000_000 < incident.ts_us:
                cached = None
            props = cached or await self._fetch_unit(unit)
            try:
                tail = await asyncio.wait_for(
                    asyncio.to_thread(unit_tail, unit, JOURNAL_TAIL, self._journal_factory),
                    LOOKUP_TIMEOUT,
                )
            except Exception as e:
                log.warning("cannot read the journal for %s: %r", unit, e)
        if incident.kind == "psi":
            cgroup = incident.target
        elif incident.kind == "unit_failed":  # it has usually lost its cgroup: show the slice
            cgroup = props.cgroup if props and props.cgroup else "system.slice"
        else:  # an AVC burst has no cgroup of its own
            cgroup = ""
        unit_props = dataclasses.asdict(props) if props else None
        return BundleContext(self.pressure_tree(cgroup), unit_props, tail)

    def pressure_tree(self, cgroup: str) -> dict[str, dict[str, Any]]:
        """Pressure for a cgroup and each of its parents, where readable."""
        parts = [p for p in cgroup.split("/") if p]
        out: dict[str, dict[str, Any]] = {}
        for i in range(len(parts), 0, -1):
            rel = "/".join(parts[:i])
            entry = {}
            for res in RESOURCES:
                try:
                    entry[res] = {
                        k: v.to_dict() for k, v in self.fs.read_pressure(rel, res).items()
                    }
                except (OSError, ValueError, KeyError):
                    continue
            if entry:
                out[rel] = entry
        return out
