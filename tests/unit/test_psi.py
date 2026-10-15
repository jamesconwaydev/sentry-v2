import asyncio
import os
import shutil
import sys
import time
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
        [(PATTERNS, SPEC)],
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
    assert trigger_specs([p, q]) == {(PATTERNS, SPEC)}


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
    assert (ev.stall_us, ev.window_us) == (None, None)
    assert ev.cgroup.startswith("system.slice/batch-")
    c.close()


def test_resolve_dedupes_and_prunes(fake_cgroupfs: Path) -> None:
    opener = Opener()
    c = collector(fake_cgroupfs, opener)
    c.resolve()
    c.resolve()
    assert len(opener.calls) == 2
    assert opener.calls[0] == ("system.slice/batch-1.service", "memory", "some", 150000, 1000000)
    shutil.rmtree(fake_cgroupfs / "cgroup/system.slice/batch-2.service")
    c.resolve()
    assert c.health()["triggers"] == 1
    c.close()


def test_resolve_skips_failed_open(fake_cgroupfs: Path) -> None:
    def boom(*a: object) -> int:
        raise OSError("gone")

    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        [(PATTERNS, SPEC)],
        EventQueue(1),
        open_trigger=boom,
    )
    c.resolve()
    assert c.health()["triggers"] == 0


def test_dispatch_pri_emits_and_err_closes(fake_cgroupfs: Path) -> None:
    q = EventQueue(10)
    opener = Opener()
    c = collector(fake_cgroupfs, opener, q)
    c.resolve()
    fd = next(iter(c._fds))
    c._dispatch(fd, EPOLLPRI)
    ev = asyncio.run(q.get())
    assert isinstance(ev, PsiEvent) and ev.triggered and ev.avg10 == 42.0
    assert (ev.stall_us, ev.window_us) == (150000, 1000000)
    c._dispatch(fd, EPOLLERR)
    assert fd not in c._fds
    c._dispatch(fd, EPOLLERR)  # unknown fd: ignored
    c.close()


def test_dispatch_plain_ints(fake_cgroupfs: Path) -> None:
    q = EventQueue(10)
    c = collector(fake_cgroupfs, Opener(), q)
    key = ("system.slice/nginx.service", "memory", "some", 150000, 1000000)
    c._fds[500] = key
    c._by_trigger[key] = 500
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
    for fd, mask in c._wait():
        c._dispatch(fd, mask)
    assert not c._fds
    c.close()


def test_run_samples_and_stops(fake_cgroupfs: Path) -> None:
    q = EventQueue(100)
    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        [(PATTERNS, SPEC)],
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


def test_policies_sharing_patterns_keep_distinct_triggers(fake_cgroupfs: Path) -> None:
    def pol(name: str, res: str, stall: int) -> Policy:
        when = PsiWhen(res, "some", stall, 1000000, 5.0, PATTERNS)  # type: ignore[arg-type]
        return Policy(name, "dry-run", 1.0, when, (), Path("x"))

    specs = trigger_specs(
        [pol("a", "memory", 150000), pol("b", "cpu", 100000), pol("c", "memory", 300000)]
    )
    assert len(specs) == 3
    opener = Opener()
    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        specs,
        EventQueue(10),
        open_trigger=opener,
    )
    c.resolve()
    assert len(opener.calls) == 6  # 2 cgroups x 3 distinct triggers
    assert c.health()["triggers"] == 6
    c.close()


def test_open_failure_warns_once(fake_cgroupfs: Path, caplog: pytest.LogCaptureFixture) -> None:
    def boom(*a: object) -> int:
        raise OSError("denied")

    c = PsiCollector(
        CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        [(PATTERNS, SPEC)],
        EventQueue(1),
        open_trigger=boom,
    )
    c.resolve()
    c.resolve()
    assert len([r for r in caplog.records if "failed" in r.message]) == 2  # two cgroups, once each


def test_resolve_noop_without_psi(tmp_path: Path) -> None:
    opener = Opener()
    collector(tmp_path, opener).resolve()
    assert opener.calls == []


def test_run_survives_iteration_error(fake_cgroupfs: Path) -> None:
    c = collector(fake_cgroupfs, Opener())
    c._sample_interval = 0.01
    calls = 0

    def bad() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("boom")

    c.sample_once = bad  # type: ignore[method-assign]

    async def main() -> None:
        t = asyncio.create_task(c.run())
        await asyncio.sleep(0.1)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(main())
    assert calls >= 2


class BlockingEpoll:
    """Stands in for select.epoll: the first registered trigger fires once.

    It has no fileno() on purpose. The collector must wait on the epoll
    itself rather than nest it in the event loop's epoll, because the
    kernel's check of a nested epoll consumes PSI trigger events.
    """

    def __init__(self) -> None:
        self.pending: list[tuple[int, int]] = []
        self.fired = False

    def register(self, fd: int, mask: int) -> None:
        if not self.fired:
            self.pending.append((fd, EPOLLPRI))
            self.fired = True

    def unregister(self, fd: int) -> None:
        pass

    def poll(self, timeout: float = -1) -> list[tuple[int, int]]:
        if self.pending:
            events, self.pending = self.pending, []
            return events
        time.sleep(0.01)
        return []

    def close(self) -> None:
        pass


def test_run_waits_on_the_trigger_epoll_off_the_loop(fake_cgroupfs: Path) -> None:
    q = EventQueue(100)
    c = collector(fake_cgroupfs, Opener(), q)
    c._sample_interval = 60
    c._ep = BlockingEpoll()

    def triggered() -> bool:
        return any(isinstance(e, PsiEvent) and e.triggered for e in list(q._q))

    async def main() -> None:
        t = asyncio.create_task(c.run())
        for _ in range(100):
            await asyncio.sleep(0.01)
            if triggered():
                break
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(main())
    assert triggered()


class BrokenEpoll(BlockingEpoll):
    def poll(self, timeout: float = -1) -> list[tuple[int, int]]:
        raise OSError(9, "Bad file descriptor")


def test_watcher_failure_is_reported_and_stops_the_collector(
    fake_cgroupfs: Path, caplog: pytest.LogCaptureFixture
) -> None:
    c = collector(fake_cgroupfs, Opener())
    c._sample_interval = 0.01
    c._ep = BrokenEpoll()

    async def main() -> None:
        with pytest.raises(RuntimeError, match="trigger watcher failed: OSError"):
            await asyncio.wait_for(c.run(), 5)

    asyncio.run(main())
    assert "psi trigger watcher failed" in caplog.text
    assert c._pool is None  # the worker thread is shut down with the collector


def test_health_reports_a_failed_watcher(fake_cgroupfs: Path) -> None:
    c = collector(fake_cgroupfs, Opener())
    c._watch_error = "OSError: boom"
    assert c.health()["state"] == "error"
    assert c.health()["watcher_error"] == "OSError: boom"
