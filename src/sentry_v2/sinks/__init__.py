"""Bundle sinks and the manager that feeds them, one queue and worker per sink."""

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
    """A sink that keeps undelivered bundles on disk and resends them with `flush`."""

    name: str
    spool: Spool

    async def send(self, bundle: Bundle) -> None: ...

    async def flush(self) -> None: ...


class SinkManager:
    """Fans bundles out to sinks without ever blocking the caller.

    A full queue spills to the sink's spool if it has one; otherwise the
    bundle is dropped and counted in `dropped`.
    """

    def __init__(self, sinks: Iterable[Sink], queue_size: int = 1000) -> None:
        self.sinks = list(sinks)
        self.failures: Counter[str] = Counter()
        self.dropped: Counter[str] = Counter()
        self._queues = {s.name: asyncio.Queue[Bundle](queue_size) for s in self.sinks}
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
                self._queues[sink.name].put_nowait(bundle)
            except asyncio.QueueFull:
                self._overflow(sink, bundle)
            except Exception:
                log.exception("sink %s: could not queue bundle", sink.name)
                self.dropped[sink.name] += 1

    def _overflow(self, sink: Sink, bundle: Bundle) -> None:
        if not isinstance(sink, Spooled):
            log.warning("sink %s: queue full, dropping bundle %s", sink.name, bundle.get("id"))
            self.dropped[sink.name] += 1
            return
        # ponytail: one task per spilled bundle, unbounded; a sustained flood queues
        # threads on the default executor. Bound with a semaphore if that shows up.
        task = asyncio.create_task(asyncio.to_thread(sink.spool.push, bundle))
        self._spilling.add(task)
        task.add_done_callback(lambda t: self._spilled(sink.name, t))

    def _spilled(self, name: str, task: asyncio.Task[None]) -> None:
        self._spilling.discard(task)
        if not task.cancelled() and (e := task.exception()):
            log.error("sink %s: could not spool bundle: %s", name, e)
            self.dropped[name] += 1

    async def _work(self, sink: Sink, queue: asyncio.Queue[Bundle]) -> None:
        if isinstance(sink, Spooled):
            try:
                await sink.flush()
            except Exception as e:
                log.warning("sink %s: resending spooled bundles failed: %s", sink.name, e)
                self.failures[sink.name] += 1
        while True:
            bundle = await queue.get()
            try:
                await sink.send(bundle)
            except asyncio.CancelledError:
                if not isinstance(sink, Spooled):  # a spooled sink already has it on disk
                    self.dropped[sink.name] += 1
                raise
            except Exception as e:
                log.warning("sink %s: bundle %s not delivered: %s", sink.name, bundle.get("id"), e)
                self.failures[sink.name] += 1
            finally:
                queue.task_done()

    async def close(self, timeout: float = 5.0) -> None:
        """Deliver what can go within `timeout`; spool or count the rest."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(*(q.join() for q in self._queues.values())), timeout
            )
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for sink in self.sinks:
            queue = self._queues[sink.name]
            while not queue.empty():
                self._overflow(sink, queue.get_nowait())
        await asyncio.gather(*self._spilling, return_exceptions=True)


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
