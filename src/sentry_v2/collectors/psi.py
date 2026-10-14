"""PSI collector: kernel triggers (EPOLLPRI) plus periodic average sampling."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import select
import time
from collections.abc import Callable, Iterable, Mapping
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

DISABLED_HINT = "PSI is off: run 'grubby --update-kernel=ALL --args=psi=1' and reboot"

Resource = Literal["memory", "cpu", "io"]
Kind = Literal["some", "full"]
Key = tuple[str, Resource, Kind]  # (cgroup, resource, kind)


@dataclass(frozen=True)
class TriggerSpec:
    resource: Resource
    kind: Kind
    stall_us: int
    window_us: int


def trigger_specs(policies: Iterable[Policy]) -> dict[tuple[str, ...], TriggerSpec]:
    """One spec per distinct cgroup-pattern tuple used by a PSI policy."""
    return {
        w.cgroups: TriggerSpec(w.resource, w.kind, w.stall_us, w.window_us)
        for p in policies
        if isinstance(w := p.when, PsiWhen)
    }


class PsiCollector:
    def __init__(
        self,
        fs: CgroupFS,
        specs: Mapping[tuple[str, ...], TriggerSpec],
        queue: EventQueue,
        clock: Callable[[], int] = lambda: time.time_ns() // 1000,
        sample_interval: float = 5.0,
        resolve_interval: float = 30.0,
        open_trigger: Callable[[str, str, str, int, int], int] | None = None,
    ) -> None:
        self._fs = fs
        self._specs = specs
        self._queue = queue
        self._clock = clock
        self._sample_interval = sample_interval
        self._resolve_interval = resolve_interval
        self._open = open_trigger or fs.open_trigger
        self._fds: dict[int, Key] = {}
        self._by_trigger: dict[tuple[str, Resource, Kind, int, int], int] = {}
        self._ep: Any = select.epoll() if hasattr(select, "epoll") else None

    def health(self) -> dict[str, object]:
        if not self._fs.psi_available():
            return {"state": "disabled", "hint": DISABLED_HINT}
        return {"state": "ok", "triggers": len(self._fds)}

    def resolve(self) -> None:
        """Open triggers for new matching cgroups and close those that vanished."""
        wanted: dict[tuple[str, Resource, Kind, int, int], None] = {}
        for patterns, s in self._specs.items():
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
                log.warning("psi trigger on %s failed: %s", key[0], e)
                continue
            self._fds[fd] = key[:3]
            self._by_trigger[key] = fd
            if self._ep is not None:
                self._ep.register(fd, EPOLLPRI)

    def _close(self, fd: int) -> None:
        self._fds.pop(fd, None)
        for k in [k for k, v in self._by_trigger.items() if v == fd]:
            del self._by_trigger[k]
        if self._ep is not None:
            with contextlib.suppress(OSError, ValueError):
                self._ep.unregister(fd)
        with contextlib.suppress(OSError):
            os.close(fd)

    def close(self) -> None:
        for fd in list(self._fds):
            self._close(fd)

    def _emit(self, key: Key, triggered: bool) -> None:
        rel, resource, kind = key
        try:
            line = self._fs.read_pressure(rel, resource)[kind]
        except (OSError, KeyError):
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

    def _on_epoll(self) -> None:
        for fd, mask in self._ep.poll(0):
            self._dispatch(fd, mask)

    def sample_once(self) -> None:
        for key in set(self._fds.values()):
            self._emit(key, triggered=False)

    async def run(self) -> None:
        if not self._fs.psi_available():
            log.warning(DISABLED_HINT)
            return
        loop = asyncio.get_running_loop()
        if self._ep is not None:
            loop.add_reader(self._ep.fileno(), self._on_epoll)
        last_resolve = float("-inf")
        try:
            while True:
                now = time.monotonic()
                if now - last_resolve >= self._resolve_interval:
                    self.resolve()
                    last_resolve = now
                self.sample_once()
                await asyncio.sleep(self._sample_interval)
        finally:
            if self._ep is not None:
                loop.remove_reader(self._ep.fileno())
            self.close()
