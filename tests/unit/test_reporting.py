import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from contracts import NGINX
from sentry_v2 import reporting
from sentry_v2.bundle import HostInfo, Redactor
from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.events import Incident, UnitEvent
from sentry_v2.reporting import Reporter
from sentry_v2.systemd import FakeSystemd


class Hung(FakeSystemd):
    """get_properties never answers until `hang` is set."""

    def __init__(self) -> None:
        super().__init__(units={"nginx.service": NGINX})
        self.hang = asyncio.Event()

    async def get_properties(self, unit: str) -> Any:
        self.calls.append(("get_properties", unit))
        await self.hang.wait()
        return await super().get_properties(unit)


def failure(unit: str = "nginx.service") -> Incident:
    ev = UnitEvent(ts_us=time.time_ns() // 1000, unit=unit, kind="failed", result="exit-code")
    return Incident(
        "0199e2c4-0000-7000-8000-000000000001", "unit_failed", ev.ts_us, unit, ev, (), ()
    )


def reporter(root: Path, mgr: FakeSystemd, out: list[dict[str, Any]]) -> Reporter:
    fs = CgroupFS(root / "cgroup", root / "proc")
    host = HostInfo("h", None, "k", None)
    return Reporter(fs, mgr, lambda: (_ for _ in ()).throw(OSError("no journal")), host,
                    Redactor(()), out.append)  # fmt: skip


def test_slow_systemd_does_not_hold_up_bundles(
    fake_cgroupfs: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reporting, "LOOKUP_TIMEOUT", 0.1)
    (fake_cgroupfs / "cgroup" / "system.slice" / "memory.pressure").write_text(
        "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n"
    )
    mgr = Hung()
    out: list[dict[str, Any]] = []
    r = reporter(fake_cgroupfs, mgr, out)

    async def main() -> None:
        r.refresh("nginx.service")  # takes the one lookup slot and hangs there
        await asyncio.sleep(0)
        await r.sinks_notify(failure(), [])  # returns at once: built in the background
        for _ in range(200):
            if out:
                break
            await asyncio.sleep(0.01)
        (bundle,) = out
        assert bundle["context"]["unit"] is None
        assert bundle["context"]["journal"] == []
        assert "system.slice" in bundle["context"]["psi"]  # the failed unit's slice
        # the bundle's own lookup timed out waiting for the slot and was dropped
        assert mgr.calls.count(("get_properties", "nginx.service")) == 1
        await r.drain(0.1)  # cancels the hung refresh

    asyncio.run(main())


def test_cached_props_are_reused_and_drain_waits_for_bundles(fake_cgroupfs: Path) -> None:
    mgr = FakeSystemd(units={"nginx.service": NGINX})
    out: list[dict[str, Any]] = []
    r = reporter(fake_cgroupfs, mgr, out)

    async def main() -> None:
        r.refresh("nginx.service")
        r.refresh("nginx.service")  # fresh, or already in flight: no second fetch
        await asyncio.sleep(0.01)
        assert r.unit_info("nginx.service") == ({"nginx"}, None)
        await r.sinks_notify(failure(), [])
        await r.drain(5)
        (bundle,) = out
        assert bundle["context"]["unit"]["exec_start"] == ["/usr/sbin/nginx"]
        assert "system.slice/nginx.service" in bundle["context"]["psi"]
        assert mgr.calls == [("get_properties", "nginx.service")]
        await r.alert("breaker_open", {})
        assert out[-1]["severity"] == "critical"

    asyncio.run(main())


def test_prune_drops_stale_unit_info(fake_cgroupfs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r = reporter(fake_cgroupfs, FakeSystemd(units={"nginx.service": NGINX}), [])

    async def main() -> None:
        r.refresh("nginx.service")
        await asyncio.sleep(0.01)
        monkeypatch.setattr(reporting, "UNIT_INFO_TTL", 0.0)
        r.prune()
        assert r.unit_info("nginx.service") == (set(), None)

    asyncio.run(main())
