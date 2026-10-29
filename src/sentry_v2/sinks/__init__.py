"""Bundle sinks and the manager that feeds them, one worker per sink."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..config_types import SinksConfig
from .base import Bundle, Sink, SinkError, load_secret
from .elastic import ElasticSink
from .file import FileSink
from .http import tls_context
from .splunk import SplunkHecSink
from .spool import Spool
from .syslog import SyslogSink
from .webhook import WebhookSink

__all__ = ["Sink", "SinkError", "SinkManager", "build_sinks"]

log = logging.getLogger(__name__)


@runtime_checkable
class Spooled(Protocol):
    """A sink that keeps undelivered bundles on disk and delivers them with `flush`."""

    name: str
    spool: Spool

    async def send(self, bundle: Bundle) -> None: ...

    async def flush(self) -> None: ...


class SinkManager:
    """Fans bundles out to sinks without ever blocking the caller.

    A spooled sink gets each bundle written to its spool at once, and its
    worker drains the spool, so a delivery stuck in backoff holds nothing in
    memory that a crash could lose. Other sinks get an in-memory queue; when
    it's full the bundle is dropped and counted in `dropped`.
    """

    def __init__(self, sinks: Iterable[Sink], queue_size: int = 1000) -> None:
        self.sinks = list(sinks)
        self.failures: Counter[str] = Counter()
        self.dropped: Counter[str] = Counter()
        self._queues = {s.name: asyncio.Queue[Bundle](queue_size) for s in self.sinks}
        # spooled sinks: `wake` means something new is on disk, `idle` that the worker waits for it
        self._wake = {s.name: asyncio.Event() for s in self.sinks}
        self._idle = {s.name: asyncio.Event() for s in self.sinks}
        self._tasks: list[asyncio.Task[None]] = []
        self._spilling: set[asyncio.Task[None]] = set()

    def start(self) -> None:
        """Start one worker per sink. Needs a running loop."""
        self._tasks = [
            asyncio.create_task(self._work(s, self._queues[s.name]), name=f"sink-{s.name}")
            for s in self.sinks
        ]

    def submit(self, bundle: Bundle) -> None:
        for sink in self.sinks:
            try:
                if isinstance(sink, Spooled):
                    self._spool(sink, bundle)
                else:
                    self._queues[sink.name].put_nowait(bundle)
            except asyncio.QueueFull:
                log.warning("sink %s: queue full, dropping bundle %s", sink.name, bundle.get("id"))
                self.dropped[sink.name] += 1
            except Exception:
                log.exception("sink %s: could not queue bundle", sink.name)
                self.dropped[sink.name] += 1

    def _spool(self, sink: Spooled, bundle: Bundle) -> None:
        # Known limit: one task per spooled bundle, unbounded, so a sustained flood
        # queues work on the default executor (upgrade path: bound it with a semaphore).
        task = asyncio.create_task(asyncio.to_thread(sink.spool.push, bundle))
        self._spilling.add(task)
        task.add_done_callback(lambda t: self._spilled(sink.name, t))

    def _spilled(self, name: str, task: asyncio.Task[None]) -> None:
        self._spilling.discard(task)
        if not task.cancelled() and (e := task.exception()):
            log.error("sink %s: could not spool bundle: %s", name, e)
            self.dropped[name] += 1
            return
        self._idle[name].clear()
        self._wake[name].set()

    async def _drain(self, sink: Spooled) -> None:
        """Deliver the spool at start and again after every push."""
        wake, idle = self._wake[sink.name], self._idle[sink.name]
        while True:
            try:
                await sink.flush()
            except Exception as e:
                log.warning("sink %s: spooled bundles not delivered: %s", sink.name, e)
                self.failures[sink.name] += 1
            if not wake.is_set():
                idle.set()
            await wake.wait()
            wake.clear()
            idle.clear()

    async def _work(self, sink: Sink, queue: asyncio.Queue[Bundle]) -> None:
        if isinstance(sink, Spooled):
            return await self._drain(sink)
        while True:
            bundle = await queue.get()
            try:
                await sink.send(bundle)
            except asyncio.CancelledError:
                self.dropped[sink.name] += 1
                raise
            except Exception as e:
                log.warning("sink %s: bundle %s not delivered: %s", sink.name, bundle.get("id"), e)
                self.failures[sink.name] += 1
            finally:
                queue.task_done()

    async def close(self, timeout: float = 5.0) -> None:
        """Deliver what can go within `timeout`; drop and count the rest, unless spooled."""
        await asyncio.gather(*self._spilling, return_exceptions=True)
        done = [
            self._idle[s.name].wait() if isinstance(s, Spooled) else self._queues[s.name].join()
            for s in self.sinks
        ]
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.gather(*done), timeout)
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for sink in self.sinks:
            queue = self._queues[sink.name]
            while not queue.empty():
                queue.get_nowait()
                self.dropped[sink.name] += 1


def build_sinks(cfg: SinksConfig, state_dir: Path, *, check_owner: bool = True) -> list[Sink]:
    """Construct every configured sink, reading secrets now so a bad one fails at startup."""

    def secret(path: Path | None, what: str) -> str:
        if path is None:
            raise SinkError(f"{what} is required")
        return load_secret(path, check_owner=check_owner)

    sinks: list[Sink] = [FileSink(cfg.file.dir, cfg.file.max_age, cfg.file.max_size)]
    if w := cfg.webhook:
        sinks.append(
            WebhookSink(
                w.url,
                secret(w.hmac_key_file, "sinks.webhook.hmac_key_file"),
                tls_context(w.ca_file),
                Spool(state_dir / "spool" / "webhook"),
                timeout=w.timeout,
            )
        )
    if s := cfg.syslog:
        ctx = tls_context(s.ca_file) if s.transport == "tls" else None
        sinks.append(SyslogSink(s.host, s.port, s.transport, ctx))
    if h := cfg.splunk_hec:
        token = secret(h.token_file, "sinks.splunk_hec.token_file")
        sinks.append(SplunkHecSink(h.url, token, h.index, tls_context(h.ca_file)))
    if e := cfg.elastic:
        if e.api_key_file is not None:
            auth = ElasticSink.api_key(secret(e.api_key_file, "sinks.elastic.api_key_file"))
        else:
            password = secret(e.password_file, "sinks.elastic.password_file")
            auth = ElasticSink.basic(e.username or "", password)
        sinks.append(ElasticSink(e.url, e.index, auth, tls_context(e.ca_file)))
    return sinks
