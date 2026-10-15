"""The daemon: wires collectors, correlation, policy, actions and sinks together.

Startup order matters. Whatever an earlier run left applied is rolled back
(replay) before any collector can raise a new incident; sinks start after
that, holding anything replay queued for them. READY=1 goes out only once
every part is running.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import grp
import logging
import os
import signal
import sys
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Coroutine, Iterable
from pathlib import Path
from typing import Any, ClassVar, Protocol

from . import __version__
from .bundle import BundleContext, HostInfo, Redactor, build_alert_bundle, build_bundle
from .cgroupfs import CgroupFS
from .collectors.audit import AuditCollector, Source, open_source
from .collectors.journal import JournalCollector, ReaderLike, open_reader, unit_tail
from .collectors.psi import PsiCollector, trigger_specs
from .commands import Commands
from .config import ConfigError, load_config
from .config_types import Config
from .control import ControlServer
from .correlate import Correlator
from .events import EventQueue, Incident, PsiEvent, UnitEvent
from .executor import Executor
from .metrics import ACTIONS_ACTIVE, PSI_AVG10, MetricsServer, build_registry
from .policy import Policy, PolicyEngine, PsiWhen, effective_mode
from .sinks import Sink, SinkError, SinkManager, build_sinks
from .state import ActionJournal, ActionRecord
from .systemd import DBusSystemd, SystemdManager

log = logging.getLogger(__name__)

TICK = 0.25  # correlator tick
HEALTHY_AFTER = 300.0  # a collector that ran this long restarts from the minimum backoff
UNIT_INFO_TTL = 60.0
SAMPLE_TTL = 300.0
INCIDENT_HISTORY = 500
RECENT_ACTIONS = 100
JOURNAL_TAIL = 50
MUTATING = {"rollback", "pause", "resume", "reload", "restore"}
RESOURCES = ("memory", "cpu", "io")


def sd_notify(state: str) -> None:
    """Tell systemd about our state; a no-op without python3-systemd or NOTIFY_SOCKET."""
    try:
        from systemd import daemon
    except ImportError:
        return
    daemon.notify(state)  # pragma: no cover


class Collector(Protocol):
    async def run(self) -> None: ...
    def health(self) -> dict[str, object]: ...


class _Journal(ActionJournal):
    """The action journal, also reporting every transition to the daemon."""

    def __init__(self, path: Path, clock: Callable[[], float], on_append: Callable[..., None]):
        super().__init__(path, clock)
        self._on_append = on_append

    def append(self, rec: ActionRecord) -> None:
        super().append(rec)
        self._on_append(rec)


def _psi_whens(policies: Iterable[Policy]) -> list[PsiWhen]:
    return [p.when for p in policies if isinstance(p.when, PsiWhen)]


def _gid(name: str) -> int | None:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        log.warning("group %s does not exist; the control socket will not admit it", name)
        return None


def _watchdog_interval() -> float | None:
    usec, pid = os.environ.get("WATCHDOG_USEC"), os.environ.get("WATCHDOG_PID")
    if not usec or (pid and pid != str(os.getpid())):
        return None
    try:
        return int(usec) / 2e6
    except ValueError:
        return None


class Daemon:
    def __init__(
        self,
        config_paths: tuple[Path, Path],
        *,
        fs: CgroupFS,
        mgr_factory: Callable[[], SystemdManager],
        journal_reader_factory: Callable[[], ReaderLike],
        audit_source_factory: Callable[[], Source],
        clock: Callable[[], float] = time.time,
        sinks_factory: Callable[[Config], list[Sink]] | None = None,
        notify: Callable[[str], object] = sd_notify,
        backoff: tuple[float, float] = (1.0, 60.0),
    ) -> None:
        self.paths = config_paths
        self.cfg = cfg = load_config(*config_paths)
        self.fs = fs
        self.clock = clock
        self._journal_factory = journal_reader_factory
        self._audit_factory = audit_source_factory
        self._sinks_factory = sinks_factory or (lambda c: build_sinks(c.sinks, c.daemon.state_dir))
        self._notify = notify
        self._backoff = backoff

        self.paused = False
        self.last_reload_error: str | None = None
        self.incidents: deque[dict[str, Any]] = deque(maxlen=INCIDENT_HISTORY)
        self.recent: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.samples: dict[tuple[str, str, str], PsiEvent] = {}
        self.ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._reload_lock = asyncio.Lock()
        self._started = time.monotonic()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._collector_tasks: dict[str, asyncio.Task[None]] = {}
        self._collectors: dict[str, Collector] = {}
        self._health: dict[str, dict[str, Any]] = {}
        self._psi: PsiCollector | None = None
        self._exec_names: dict[str, tuple[float, set[str]]] = {}
        self._incident_count = 0
        self._seen_dropped: Counter[str] = Counter()
        self._seen_failures: Counter[str] = Counter()

        self.queue = EventQueue(cfg.daemon.queue_size)
        self.host = HostInfo.collect()
        self.redactor = Redactor.from_config(cfg.redaction)
        self.engine = PolicyEngine(cfg.policies, clock)
        self.correlator = Correlator(
            cfg.correlation, _psi_whens(cfg.policies), clock, self._unit_info
        )
        self.mgr = mgr_factory()
        state = cfg.daemon.state_dir
        journal = _Journal(state / "state" / "actions.jsonl", clock, self._on_record)
        self.executor = Executor(
            self.mgr, fs, journal, cfg.limits, cfg.protection, self._sinks_notify,
            self.alert, clock, state / "backups", daemon_mode=cfg.daemon.mode,
        )  # fmt: skip
        self.sinks = SinkManager(self._sinks_factory(cfg))
        self.registry, self.metrics = build_registry({"version": __version__})
        self.registry.gauge_func(PSI_AVG10, "PSI avg10 from the latest samples.", self._psi_rows)
        self.registry.gauge_func(
            ACTIONS_ACTIVE, "Throttles and freezes awaiting rollback.",
            lambda: [({}, len(self.executor.active()))],
        )  # fmt: skip
        self.metrics_server = (
            MetricsServer(self.registry, cfg.metrics.host, cfg.metrics.port)
            if cfg.metrics.enabled
            else None
        )
        self.commands = Commands(self)
        ctl = cfg.control
        self.control = ControlServer(
            ctl.socket, self.commands.handlers(), _gid(ctl.group), _gid(ctl.admin_group), MUTATING
        )

    # -- lifecycle ---------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    def uptime(self) -> float:
        return time.monotonic() - self._started

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        handlers = {
            signal.SIGTERM: self.stop,
            signal.SIGINT: self.stop,
            signal.SIGHUP: lambda: self._spawn(self.reload()),
        }
        for sig, fn in handlers.items():
            loop.add_signal_handler(sig, fn)
        try:
            await self.executor.replay()
            self.sinks.start()
            if self.metrics_server is not None:
                await self.metrics_server.start()
            await self.control.start()
            for name in ("psi", "journal", "audit"):
                self._start_collector(name)
            self._spawn(self._consume())
            self._spawn(self._ticker())
            if (interval := _watchdog_interval()) is not None:
                self._spawn(self._watchdog(interval))
            self._notify("READY=1")
            self._status_line()
            self.ready.set()
            log.info(
                "started: %d policies, daemon mode %s", len(self.cfg.policies), self.cfg.daemon.mode
            )
            await self._stop.wait()
        finally:
            for sig in handlers:
                loop.remove_signal_handler(sig)
            await self._shutdown()

    async def _shutdown(self) -> None:
        self._notify("STOPPING=1")
        log.info("stopping: rolling back %d active actions", len(self.executor.active()))
        await self.control.stop()
        tasks = [*self._collector_tasks.values(), *self._tasks]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.executor.shutdown()
        await self.sinks.close(5)
        if self.metrics_server is not None:
            await self.metrics_server.stop()
        if isinstance(self.mgr, DBusSystemd):
            self.mgr.close()

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _watchdog(self, interval: float) -> None:
        while True:  # on the main loop, so a hung loop stops the pings
            self._notify("WATCHDOG=1")
            await asyncio.sleep(interval)

    def _status_line(self) -> None:
        self._notify(
            f"STATUS=mode {self.cfg.daemon.mode}{' (paused)' if self.paused else ''}, "
            f"{len(self.cfg.policies)} policies, {len(self.executor.active())} active actions, "
            f"{self._incident_count} incidents"
        )

    # -- collectors --------------------------------------------------------

    def _make(self, name: str) -> Collector:
        clock_us = lambda: int(self.clock() * 1_000_000)  # noqa: E731
        if name == "psi":
            specs = trigger_specs(self.cfg.policies)
            self._psi = PsiCollector(self.fs, specs, self.queue, clock=clock_us)
            return self._psi
        if name == "journal":
            return JournalCollector(self.queue, self._journal_factory, self._units_changed)
        return AuditCollector(self.queue, self.fs, self._audit_factory, clock=clock_us)

    def _units_changed(self) -> None:
        if self._psi is not None:
            self._psi.resolve()

    def _start_collector(self, name: str) -> None:
        self._collector_tasks[name] = asyncio.create_task(self._supervise(name), name=name)

    async def _supervise(self, name: str) -> None:
        """Run a collector, restarting it with backoff whenever it stops.

        Collectors never retry on their own. One that reports itself
        disabled (PSI off in the kernel) is left stopped.
        """
        delay = self._backoff[0]
        health = self._health[name] = {"restarts": 0, "last_error": None}
        while True:
            collector = self._collectors[name] = self._make(name)
            began = time.monotonic()
            try:
                await collector.run()
                error = "stopped"
            except Exception as e:
                log.exception("collector %s crashed", name)
                error = f"{type(e).__name__}: {e}"
            if collector.health().get("state") == "disabled":
                return
            if time.monotonic() - began >= HEALTHY_AFTER:
                delay = self._backoff[0]
            health["restarts"] += 1
            health["last_error"] = error
            log.warning("collector %s stopped (%s); restarting in %gs", name, error, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._backoff[1])

    def collector_health(self) -> dict[str, dict[str, Any]]:
        return {n: {**c.health(), **self._health[n]} for n, c in self._collectors.items()}

    # -- event pipeline ----------------------------------------------------

    async def _consume(self) -> None:
        while True:
            ev = await self.queue.get()
            try:
                if isinstance(ev, PsiEvent):
                    self.samples[(ev.cgroup, ev.resource, ev.kind)] = ev
                elif isinstance(ev, UnitEvent):
                    self._refresh_unit(ev.unit)
                for incident in self.correlator.ingest(ev):
                    await self._handle(incident)
            except Exception:
                log.exception("handling %s failed", type(ev).__name__)

    async def _ticker(self) -> None:
        while True:
            await asyncio.sleep(TICK)
            try:
                now = self.clock()
                for incident in self.correlator.tick(int(now * 1_000_000)):
                    await self._handle(incident)
                horizon = (now - SAMPLE_TTL) * 1_000_000
                self.samples = {k: s for k, s in self.samples.items() if s.ts_us >= horizon}
                self._sync_counters()
            except Exception:
                log.exception("correlator tick failed")

    async def _handle(self, incident: Incident) -> None:
        self._incident_count += 1
        self.metrics.incidents_total.labels(kind=incident.kind).inc()
        if incident.correlations:
            self.metrics.avc_correlated_total.inc(len(incident.correlations))
        records = await self.executor.handle(incident, self.engine.plan(incident))
        for r in records:
            self.metrics.actions_total.labels(
                policy=r.policy, action=r.action, mode=r.mode, result=r.status
            ).inc()
        self._status_line()

    def _sync_counters(self) -> None:
        pairs = (
            (
                self.metrics.events_dropped_total,
                "collector",
                self.queue.dropped,
                self._seen_dropped,
            ),
            (self.metrics.sink_failures_total, "sink", self.sinks.failures, self._seen_failures),
        )
        for metric, label, counts, seen in pairs:
            for name, n in counts.items():
                if n > seen[name]:
                    metric.labels(**{label: name}).inc(n - seen[name])
                    seen[name] = n

    def _psi_rows(self) -> list[tuple[dict[str, str], float]]:
        return [
            ({"cgroup": cg, "resource": res, "kind": kind}, ev.avg10)
            for (cg, res, kind), ev in self.samples.items()
        ]

    # -- unit info for correlation -----------------------------------------

    def _unit_info(self, unit: str) -> tuple[set[str], str | None]:
        """Called synchronously by the correlator: whatever is cached right now."""
        return self._exec_names.get(unit, (0.0, set()))[1], None

    def _refresh_unit(self, unit: str) -> None:
        fetched, names = self._exec_names.get(unit, (float("-inf"), set()))
        if time.monotonic() - fetched < UNIT_INFO_TTL:
            return
        self._exec_names[unit] = (time.monotonic(), names)  # one fetch in flight per unit
        self._spawn(self._fetch_unit(unit))

    async def _fetch_unit(self, unit: str) -> None:
        try:
            props = await self.mgr.get_properties(unit)
        except Exception as e:
            log.debug("no properties for %s: %s", unit, e)
            return
        self._exec_names[unit] = (
            time.monotonic(),
            {p.rsplit("/", 1)[-1] for p in props.exec_start},
        )

    # -- bundles and records -----------------------------------------------

    def _on_record(self, rec: ActionRecord) -> None:
        d = {**dataclasses.asdict(rec), "ts": self.clock()}
        self.recent.pop(rec.id, None)
        self.recent[rec.id] = d
        while len(self.recent) > RECENT_ACTIONS:
            self.recent.popitem(last=False)
        self.control.publish({"type": "action", "record": d})

    def record_dict(self, rec: ActionRecord) -> dict[str, Any]:
        return self.recent.get(rec.id) or {**dataclasses.asdict(rec), "ts": rec.applied_at}

    def _submit(self, bundle: dict[str, Any]) -> None:
        self.sinks.submit(bundle)
        inc = bundle["incident"]
        summary = {
            "id": bundle["id"], "ts": bundle["ts"], "severity": bundle["severity"],
            "kind": inc["kind"], "target": inc["target"], "policy": bundle["decision"]["policy"],
        }  # fmt: skip
        self.incidents.appendleft(summary)
        self.control.publish({"type": "incident", "incident": summary})

    async def _sinks_notify(self, incident: Incident, records: list[ActionRecord]) -> None:
        context = await self._context(incident)
        rows = [dataclasses.asdict(r) for r in records]
        self._submit(build_bundle(incident, rows, context, self.host, self.redactor))

    async def alert(self, kind: str, detail: dict[str, Any]) -> None:
        self._submit(build_alert_bundle(kind, detail, self.host))

    async def _context(self, incident: Incident) -> BundleContext:
        unit = None
        if incident.kind == "unit_failed":
            unit = incident.target
        elif incident.kind == "psi":
            unit = self.fs.unit_of(incident.target)
        props = None
        tail: list[dict[str, Any]] = []
        if unit is not None:
            try:
                props = await self.mgr.get_properties(unit)
            except Exception as e:
                log.debug("no properties for %s: %s", unit, e)
            try:
                tail = await asyncio.to_thread(unit_tail, unit, JOURNAL_TAIL, self._journal_factory)
            except Exception as e:
                log.warning("cannot read the journal for %s: %s", unit, e)
        cgroup = incident.target if incident.kind == "psi" else props.cgroup if props else ""
        unit_props = dataclasses.asdict(props) if props else None
        return BundleContext(self._pressure_tree(cgroup), unit_props, tail)

    def _pressure_tree(self, cgroup: str) -> dict[str, dict[str, Any]]:
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

    # -- reload --------------------------------------------------------------

    async def reload(self) -> str | None:
        """Re-read the configuration; on error keep the running one and return the error."""
        async with self._reload_lock:
            self._notify(f"RELOADING=1\nMONOTONIC_USEC={time.monotonic_ns() // 1000}")
            try:
                return await self._reload()
            finally:
                self._notify("READY=1")
                self._status_line()

    async def _reload(self) -> str | None:
        try:
            cfg = load_config(*self.paths)
            sinks = SinkManager(self._sinks_factory(cfg))
        except (ConfigError, SinkError) as e:
            self.last_reload_error = str(e)
            log.error("reload failed; keeping the running configuration: %s", e)
            return str(e)
        old = self.cfg
        fixed = ("control", "metrics")
        if any(getattr(cfg, f) != getattr(old, f) for f in fixed) or (
            cfg.daemon.state_dir,
            cfg.daemon.queue_size,
        ) != (old.daemon.state_dir, old.daemon.queue_size):
            log.warning("control, metrics, state_dir and queue_size changes need a restart")
        self._sync_counters()
        self._seen_failures.clear()
        old_sinks, self.sinks = self.sinks, sinks
        sinks.start()
        self.cfg = cfg
        self.engine.replace(cfg.policies)
        self.executor.mode = cfg.daemon.mode
        self.executor.limits = cfg.limits
        self.executor.protection = cfg.protection
        self.redactor = Redactor.from_config(cfg.redaction)
        self.correlator.configure(cfg.correlation, _psi_whens(cfg.policies))
        logging.getLogger("sentry_v2").setLevel(cfg.daemon.log_level.upper())
        if (task := self._collector_tasks.get("psi")) is not None:
            task.cancel()  # the old collector closes its triggers on the way out
            await asyncio.gather(task, return_exceptions=True)
            self._start_collector("psi")
        self.last_reload_error = None
        log.info("reloaded: %d policies, daemon mode %s", len(cfg.policies), cfg.daemon.mode)
        await old_sinks.close(5)
        return None


# -- entry point ----------------------------------------------------------------


class JournalFormatter(logging.Formatter):
    """Prefixes each record with `<priority>` so journald files it at the right level."""

    PRIORITY: ClassVar[dict[int, int]] = {
        logging.DEBUG: 7,
        logging.INFO: 6,
        logging.WARNING: 4,
        logging.ERROR: 3,
        logging.CRITICAL: 2,
    }

    def format(self, record: logging.LogRecord) -> str:
        prio = self.PRIORITY.get(record.levelno, 6)
        return f"<{prio}>{record.name}: {super().format(record)}"


def _check(config: Path, policies: Path) -> int:
    try:
        cfg = load_config(config, policies)
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    mode = cfg.daemon.mode
    print(f"{config}: OK, {len(cfg.policies)} policies, daemon mode {mode}")
    for p in cfg.policies:
        print(f"  {p.name}: {p.mode} (effective {effective_mode(mode, p.mode)}) from {p.source}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentry-v2", description="The sentry-v2 daemon.")
    parser.add_argument("--config", type=Path, default=Path("/etc/sentry-v2/sentry-v2.toml"))
    parser.add_argument("--policies", type=Path, default=Path("/etc/sentry-v2/policies.d"))
    parser.add_argument("--check", action="store_true", help="validate the configuration and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.check:
        return _check(args.config, args.policies)

    handler = logging.StreamHandler()
    handler.setFormatter(JournalFormatter("%(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    try:
        daemon = Daemon(
            (args.config, args.policies),
            fs=CgroupFS(),
            mgr_factory=DBusSystemd,
            journal_reader_factory=open_reader,
            audit_source_factory=open_source,
        )
    except (ConfigError, SinkError) as e:
        print(e, file=sys.stderr)
        return 2
    logging.getLogger("sentry_v2").setLevel(daemon.cfg.daemon.log_level.upper())
    asyncio.run(daemon.run())
    return 0
