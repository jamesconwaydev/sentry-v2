"""PSI collector: kernel triggers (EPOLLPRI) plus periodic average sampling."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import select
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Literal

from ..cgroupfs import CgroupFS
from ..events import EventQueue, PsiEvent
from ..policy import Policy, PsiWhen

log = logging.getLogger(__name__)

# Linux values; select.EPOLL* does not exist on macOS.
EPOLLPRI = 0x002
EPOLLERR = 0x008
EPOLLHUP = 0x010
WAIT_TIMEOUT = 1.0  # seconds; bounds how long cancelling the watcher takes

DISABLED_HINT = "PSI is off: run 'grubby --update-kernel=ALL --args=psi=1' and reboot"

Resource = Literal["memory", "cpu", "io"]
Kind = Literal["some", "full"]
# (cgroup, resource, kind, stall_us, window_us): one kernel trigger each
Key = tuple[str, Resource, Kind, int, int]


@dataclass(frozen=True)
class TriggerSpec:
    resource: Resource
    kind: Kind
    stall_us: int
    window_us: int


def trigger_specs(policies: Iterable[Policy]) -> set[tuple[tuple[str, ...], TriggerSpec]]:
    """Distinct (cgroup patterns, spec) pairs across all PSI policies."""
    return {
        (w.cgroups, TriggerSpec(w.resource, w.kind, w.stall_us, w.window_us))
        for p in policies
        if isinstance(w := p.when, PsiWhen)
    }


class PsiCollector:
    def __init__(
        self,
        fs: CgroupFS,
        specs: Iterable[tuple[tuple[str, ...], TriggerSpec]],
        queue: EventQueue,
        clock: Callable[[], int] = lambda: time.time_ns() // 1000,
        sample_interval: float = 5.0,
        resolve_interval: float = 30.0,
        open_trigger: Callable[[str, str, str, int, int], int] | None = None,
    ) -> None:
        self._fs = fs
        self._specs = tuple(specs)
        self._queue = queue
        self._clock = clock
        self._sample_interval = sample_interval
        self._resolve_interval = resolve_interval
        self._open = open_trigger or fs.open_trigger
        self._fds: dict[int, Key] = {}
        self._by_trigger: dict[Key, int] = {}
        self._warned: set[Key] = set()
        self._ep: Any = None
        self._pool: ThreadPoolExecutor | None = None
        self._watch_error: str | None = None

    def _epoll(self) -> Any:
        """The epoll object, created on first use; None where epoll is absent."""
        if self._ep is None and hasattr(select, "epoll"):
            self._ep = select.epoll()
        return self._ep

    def health(self) -> dict[str, object]:
        if not self._fs.psi_available():
            return {"state": "disabled", "hint": DISABLED_HINT}
        if self._watch_error is not None:
            return {
                "state": "error",
                "triggers": len(self._fds),
                "watcher_error": self._watch_error,
            }
        return {"state": "ok", "triggers": len(self._fds)}

    def resolve(self) -> None:
        """Open triggers for new matching cgroups and close those that vanished."""
        if not self._fs.psi_available():
            return
        wanted: dict[Key, None] = {}
        for patterns, s in self._specs:
            for rel in self._fs.glob(patterns):
                wanted[(rel, s.resource, s.kind, s.stall_us, s.window_us)] = None
        for key in [k for k in self._by_trigger if k not in wanted]:
            self._close(self._by_trigger[key])
        for key in wanted:
            if key in self._by_trigger:
                continue
            try:
                fd = self._open(*key)
            except OSError as e:
                if key not in self._warned:
                    self._warned.add(key)
                    log.warning("psi trigger on %s failed: %s", key[0], e)
                continue
            self._fds[fd] = key
            self._by_trigger[key] = fd
            if (ep := self._epoll()) is not None:
                ep.register(fd, EPOLLPRI)

    def _close(self, fd: int) -> None:
        if (key := self._fds.pop(fd, None)) is not None:
            del self._by_trigger[key]
        if self._ep is not None:
            with contextlib.suppress(OSError, ValueError):
                self._ep.unregister(fd)
        with contextlib.suppress(OSError):
            os.close(fd)

    def close(self) -> None:
        if self._pool is not None:
            # a poll() in flight returns within WAIT_TIMEOUT; nobody waits for it
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
        for fd in list(self._fds):
            self._close(fd)
        if self._ep is not None:
            self._ep.close()
            self._ep = None

    def _emit(self, key: Key, triggered: bool) -> None:
        rel, resource, kind, stall_us, window_us = key
        try:
            line = self._fs.read_pressure(rel, resource)[kind]
        except (OSError, KeyError, ValueError):
            return  # cgroup vanished or kind not exposed; resolve() will prune
        self._queue.put_nowait(
            PsiEvent(
                ts_us=self._clock(),
                cgroup=rel,
                resource=resource,
                kind=kind,
                avg10=line.avg10,
                avg60=line.avg60,
                avg300=line.avg300,
                total_us=line.total_us,
                triggered=triggered,
                stall_us=stall_us if triggered else None,
                window_us=window_us if triggered else None,
            )
        )

    def _dispatch(self, fd: int, mask: int) -> None:
        key = self._fds.get(fd)
        if key is None:
            return
        if mask & (EPOLLERR | EPOLLHUP):
            self._close(fd)  # cgroup went away
        elif mask & EPOLLPRI:
            self._emit(key, triggered=True)

    def _wait(self) -> list[tuple[int, int]]:
        """Block up to WAIT_TIMEOUT for trigger events; runs in a worker thread.

        The epoll fd is never handed to the event loop. When an outer epoll
        checks a nested one, the kernel polls each PSI trigger on its behalf,
        and psi_trigger_poll() clears the event as it reports it, so the
        collector would wake up to an empty poll every time.
        """
        ep = self._ep
        return ep.poll(WAIT_TIMEOUT) if ep is not None else []

    async def _watch(self, pool: ThreadPoolExecutor) -> None:
        # Known limit: an fd closed and reopened between poll() and dispatch
        # could take one stray event. resolve() runs every 30s, so that's rare
        # (upgrade path: tag registrations with a generation number).
        loop = asyncio.get_running_loop()
        while True:
            for fd, mask in await loop.run_in_executor(pool, self._wait):
                self._dispatch(fd, mask)

    def _watcher_done(self, task: asyncio.Task[None]) -> None:
        if task.cancelled() or (e := task.exception()) is None:
            return
        log.error("psi trigger watcher failed", exc_info=e)
        self._watch_error = f"{type(e).__name__}: {e}"

    def sample_once(self) -> None:
        for key in {k[:3] for k in self._fds.values()}:
            self._emit((*key, 0, 0), triggered=False)

    async def run(self) -> None:
        if not self._fs.psi_available():
            log.warning(DISABLED_HINT)
            return
        watcher = None
        if self._epoll() is not None:
            # its own thread, so a blocked poll() never holds up asyncio.to_thread users
            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="psi-triggers")
            watcher = asyncio.create_task(self._watch(self._pool))
            watcher.add_done_callback(self._watcher_done)
        last_resolve = float("-inf")
        try:
            while True:
                try:
                    now = time.monotonic()
                    if now - last_resolve >= self._resolve_interval:
                        self.resolve()
                        last_resolve = now
                    self.sample_once()
                except Exception:
                    log.exception("psi collector iteration failed")
                if self._watch_error is not None:
                    # the daemon's supervisor restarts the collector, watcher and all
                    raise RuntimeError(f"trigger watcher failed: {self._watch_error}")
                await asyncio.sleep(self._sample_interval)
        finally:
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            self.close()
