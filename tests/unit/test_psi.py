import asyncio
import os
import sys
from pathlib import Path

import pytest

from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.collectors.psi import (
    EPOLLERR,
    EPOLLPRI,
    PsiCollector,
    TriggerSpec,
    trigger_specs,
)
from sentry_v2.events import EventQueue, PsiEvent
from sentry_v2.policy import Policy, PsiWhen, UnitFailedWhen

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="epoll is Linux-only")
SPEC = TriggerSpec("memory", "some", 150000, 1000000)
PATTERNS = ("system.slice/batch-*.service",)


class Opener:
    """Hands out pipe read-ends in place of kernel trigger fds."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.peers: list[int] = []

    def __call__(self, rel: str, resource: str, kind: str, stall: int, window: int) -> int:
        self.calls.append((rel, resource, kind, stall, window))
        r, w = os.pipe()
        self.peers.append(w)
        return r


def collector(base: Path, opener: Opener, queue: EventQueue | None = None) -> PsiCollector:
    return PsiCollector(
        CgroupFS(base / "cgroup", base / "proc"),
        {PATTERNS: SPEC},
        queue if queue is not None else EventQueue(10),
        clock=lambda: 99,
        open_trigger=opener,
    )


def test_event_queue_drops_oldest() -> None:
    q = EventQueue(2)
    evs = [
        PsiEvent(
            ts_us=i, cgroup="c", resource="cpu", kind="some",
            avg10=0, avg60=0, avg300=0, total_us=0, triggered=False,
        )
        for i in range(3)
    ]  # fmt: skip
    for e in evs:
        q.put_nowait(e)
    assert q.dropped["psi"] == 1

    async def drain() -> list[int]:
        return [(await q.get()).ts_us, (await q.get()).ts_us]

    assert asyncio.run(drain()) == [1, 2]


def test_trigger_specs() -> None:
    when = PsiWhen("memory", "some", 150000, 1000000, 5.0, PATTERNS)
    p = Policy("a", "dry-run", 1.0, when, (), Path("x"))
    q = Policy("b", "dry-run", 1.0, UnitFailedWhen(("x",)), (), Path("x"))
    assert trigger_specs([p, q]) == {PATTERNS: SPEC}


def test_disabled_when_psi_off(tmp_path: Path) -> None:
    c = collector(tmp_path, Opener())
    assert c.health() == {
        "state": "disabled",
        "hint": "PSI is off: run 'grubby --update-kernel=ALL --args=psi=1' and reboot",
    }
    asyncio.run(c.run())


def test_sample_once(fake_cgroupfs: Path) -> None:
    q = EventQueue(10)
    c = collector(fake_cgroupfs, Opener(), q)
    c.resolve()
    c.sample_once()
    ev = asyncio.run(q.get())
    assert isinstance(ev, PsiEvent)
    assert (ev.triggered, ev.avg10, ev.ts_us, ev.resource) == (False, 42.0, 99, "memory")
    assert ev.cgroup.startswith("system.slice/batch-")
    c.close()


@linux_only
def test_resolve_dedupes_and_prunes(fake_cgroupfs: Path) -> None:
    opener = Opener()
    c = collector(fake_cgroupfs, opener)
    c.resolve()
    c.resolve()
    assert len(opener.calls) == 2
    assert opener.calls[0] == ("system.slice/batch-1.service", "memory", "some", 150000, 1000000)
    (fake_cgroupfs / "cgroup/system.slice/batch-2.service/memory.pressure").unlink()
    (fake_cgroupfs / "cgroup/system.slice/batch-2.service/memory.current").unlink()
    (fake_cgroupfs / "cgroup/system.slice/batch-2.service/cpu.pressure").unlink()
    (fake_cgroupfs / "cgroup/system.slice/batch-2.service/io.pressure").unlink()
    (fake_cgroupfs / "cgroup/system.slice/batch-2.service").rmdir()
    c.resolve()
    assert c.health()["triggers"] == 1
    c.close()


def test_resolve_skips_failed_open(fake_cgroupfs: Path) -> None:
    def boom(*a: object) -> int:
        raise OSError("gone")

    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        {PATTERNS: SPEC},
        EventQueue(1),
        open_trigger=boom,
    )
    c.resolve()
    assert c.health()["triggers"] == 0


@linux_only
def test_dispatch_pri_emits_and_err_closes(fake_cgroupfs: Path) -> None:
    q = EventQueue(10)
    opener = Opener()
    c = collector(fake_cgroupfs, opener, q)
    c.resolve()
    fd = next(iter(c._fds))
    c._dispatch(fd, EPOLLPRI)
    ev = asyncio.run(q.get())
    assert isinstance(ev, PsiEvent) and ev.triggered and ev.avg10 == 42.0
    c._dispatch(fd, EPOLLERR)
    assert fd not in c._fds
    c._dispatch(fd, EPOLLERR)  # unknown fd: ignored
    c.close()


def test_dispatch_plain_ints(fake_cgroupfs: Path) -> None:
    q = EventQueue(10)
    c = collector(fake_cgroupfs, Opener(), q)
    c._fds[500] = ("system.slice/nginx.service", "memory", "some")
    c._dispatch(500, EPOLLPRI)
    assert q.dropped["psi"] == 0 and len(q) == 1
    c._dispatch(500, 0)  # neither flag: no-op
    assert len(q) == 1 and 500 in c._fds
    c._dispatch(1, EPOLLPRI)  # unknown fd
    assert len(q) == 1
    c._dispatch(500, EPOLLERR)
    assert 500 not in c._fds


@linux_only
def test_epoll_hup_closes_fd(fake_cgroupfs: Path) -> None:
    opener = Opener()
    c = collector(fake_cgroupfs, opener)
    c.resolve()
    for w in opener.peers:
        os.close(w)
    assert c._ep is not None
    c._on_epoll()
    assert not c._fds
    c.close()


@linux_only
def test_run_samples_and_stops(fake_cgroupfs: Path) -> None:
    q = EventQueue(100)
    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        {PATTERNS: SPEC},
        q,
        sample_interval=0.01,
        resolve_interval=0.02,
        open_trigger=Opener(),
    )

    async def main() -> None:
        t = asyncio.create_task(c.run())
        await asyncio.sleep(0.1)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(main())
    assert len(q) >= 2
    assert c.health()["triggers"] == 0
