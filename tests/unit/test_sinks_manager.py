import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest
from sinkfixtures import make_bundle

from sentry_v2.config_types import (
    ElasticSinkConfig,
    FileSinkConfig,
    SinksConfig,
    SplunkHecSinkConfig,
    SyslogSinkConfig,
    WebhookSinkConfig,
)
from sentry_v2.sinks import SinkManager, build_sinks
from sentry_v2.sinks.base import SinkError
from sentry_v2.sinks.elastic import ElasticSink
from sentry_v2.sinks.file import FileSink
from sentry_v2.sinks.splunk import SplunkHecSink
from sentry_v2.sinks.spool import Spool
from sentry_v2.sinks.syslog import SyslogSink
from sentry_v2.sinks.webhook import WebhookSink


class Recorder:
    def __init__(self, name: str = "rec", fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.got: list[str] = []
        self.gate = asyncio.Event()
        self.gate.set()

    async def send(self, bundle: dict[str, Any]) -> None:
        await self.gate.wait()
        if self.fail:
            raise SinkError("boom")
        self.got.append(bundle["id"])


class Spooled(Recorder):
    def __init__(self, spool: Spool) -> None:
        super().__init__("spooled")
        self.spool = spool
        self.flushed = 0

    async def flush(self) -> None:
        await self.gate.wait()
        self.flushed += 1
        if self.fail:
            raise SinkError("still down")


def test_delivers_to_every_sink_and_counts_failures() -> None:
    ok, bad = Recorder("ok"), Recorder("bad", fail=True)

    async def run() -> SinkManager:
        m = SinkManager([ok, bad])
        m.start()
        b = make_bundle()
        m.submit(b)
        await m.close()
        return m

    m = asyncio.run(run())
    assert len(ok.got) == 1
    assert m.failures == {"bad": 1}


def test_full_queue_drops(tmp_path: Path) -> None:
    plain = Recorder("plain")
    plain.gate.clear()
    bundles = [make_bundle() for _ in range(4)]

    async def run() -> SinkManager:
        m = SinkManager([plain], queue_size=1)
        m.start()
        m.submit(bundles[0])
        await asyncio.sleep(0.01)  # the worker takes bundle 0 and blocks on the gate
        for b in bundles[1:]:
            m.submit(b)
        plain.gate.set()
        await m.close()
        return m

    m = asyncio.run(run())
    # bundle 0 in flight, bundle 1 queued, bundles 2-3 overflow
    assert plain.got == [b["id"] for b in bundles[:2]]
    assert m.dropped == {"plain": 2}


def test_spooled_sink_has_every_bundle_on_disk_while_a_flush_is_stuck(tmp_path: Path) -> None:
    spooled = Spooled(Spool(tmp_path))
    spooled.gate.clear()  # the startup flush hangs, like a webhook in backoff
    bundles = [make_bundle() for _ in range(3)]

    async def run() -> SinkManager:
        m = SinkManager([spooled], queue_size=1)
        m.start()
        for b in bundles:
            m.submit(b)
        await asyncio.sleep(0.05)
        assert [b["id"] for _, b in spooled.spool.pending()] == [b["id"] for b in bundles]
        spooled.gate.set()
        await m.close()
        return m

    m = asyncio.run(run())
    assert m.dropped == {}
    assert spooled.flushed == 2  # the startup one, then one for everything pushed meanwhile


def test_submit_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    class Broken(Recorder):
        def __init__(self) -> None:
            super().__init__("broken")
            self.spool = None

    async def run() -> SinkManager:
        m = SinkManager([Broken()])
        m._queues["broken"] = None  # type: ignore[assignment]
        with caplog.at_level(logging.ERROR):
            m.submit(make_bundle())
        return m

    assert asyncio.run(run()).dropped == {"broken": 1}


def test_close_times_out_and_keeps_the_spool(tmp_path: Path) -> None:
    plain, spooled = Recorder("plain"), Spooled(Spool(tmp_path))
    plain.gate.clear()
    spooled.gate.clear()
    bundles = [make_bundle() for _ in range(3)]

    async def run() -> SinkManager:
        m = SinkManager([plain, spooled])
        m.start()
        for b in bundles:
            m.submit(b)
        await m.close(timeout=0.05)
        return m

    m = asyncio.run(run())
    assert plain.got == []
    assert m.dropped == {"plain": 3}
    assert [b["id"] for _, b in spooled.spool.pending()] == [b["id"] for b in bundles]


def test_startup_flush_failure_is_counted(tmp_path: Path) -> None:
    s = Spooled(Spool(tmp_path))
    s.fail = True

    async def run() -> SinkManager:
        m = SinkManager([s])
        m.start()
        await asyncio.sleep(0.01)
        await m.close()
        return m

    assert asyncio.run(run()).failures == {"spooled": 1}


def _secret(tmp_path: Path, name: str, text: str = "x") -> Path:
    p = tmp_path / name
    p.write_text(text + "\n")
    p.chmod(0o600)
    return p


def test_build_sinks_constructs_each_enabled_sink(tmp_path: Path) -> None:
    cfg = SinksConfig(
        file=FileSinkConfig(dir=tmp_path / "bundles"),
        webhook=WebhookSinkConfig("https://h/hook", hmac_key_file=_secret(tmp_path, "hk")),
        syslog=SyslogSinkConfig(transport="tcp"),
        splunk_hec=SplunkHecSinkConfig("https://h", token_file=_secret(tmp_path, "tok")),
        elastic=ElasticSinkConfig(
            "https://h", "idx", username="u", password_file=_secret(tmp_path, "pw")
        ),
    )
    sinks = build_sinks(cfg, tmp_path / "state", check_owner=False)
    assert [type(s) for s in sinks] == [
        FileSink,
        WebhookSink,
        SyslogSink,
        SplunkHecSink,
        ElasticSink,
    ]
    hook = sinks[1]
    assert isinstance(hook, WebhookSink)
    assert hook.spool.dir == tmp_path / "state" / "spool" / "webhook"
    es = sinks[4]
    assert isinstance(es, ElasticSink)
    assert es._auth == ElasticSink.basic("u", "x")


def test_build_sinks_file_only_and_api_key(tmp_path: Path) -> None:
    assert [type(s) for s in build_sinks(SinksConfig(), tmp_path)] == [FileSink]
    cfg = SinksConfig(
        elastic=ElasticSinkConfig("https://h", "idx", api_key_file=_secret(tmp_path, "ak", "K"))
    )
    es = build_sinks(cfg, tmp_path, check_owner=False)[1]
    assert isinstance(es, ElasticSink)
    assert es._auth == "ApiKey K"


def test_build_sinks_fails_fast_on_bad_secret(tmp_path: Path) -> None:
    key = _secret(tmp_path, "hk")
    key.chmod(0o644)
    cfg = SinksConfig(webhook=WebhookSinkConfig("https://h", hmac_key_file=key))
    with pytest.raises(SinkError, match="hk"):
        build_sinks(cfg, tmp_path, check_owner=False)
