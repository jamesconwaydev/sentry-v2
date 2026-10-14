"""HMAC-signed HTTPS webhook, spooled to disk until delivered."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import random as _random
import ssl
import time
from collections.abc import Awaitable, Callable

from .base import Bundle, SinkError, encode
from .http import TRANSIENT, post
from .spool import Spool

log = logging.getLogger(__name__)

RETRY_FOR = 3600.0
MAX_DELAY = 3600.0


def _permanent(e: SinkError) -> bool:
    """A client error that retrying cannot fix."""
    return e.status is not None and e.status < 500 and e.status not in (408, 429)


class WebhookSink:
    """Every bundle is spooled first and acked on delivery, so a crash loses nothing.

    Delivery is oldest-first: a send also drains anything spooled earlier.
    A transient failure is retried with backoff for up to an hour, then left
    in the spool for the next send or the next start. A 4xx other than
    408/429 will never succeed, so that bundle is dropped rather than left
    to block the spool.
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        key: str,
        context: ssl.SSLContext,
        spool: Spool,
        timeout: float = 10.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        random: Callable[[float, float], float] = _random.uniform,
    ) -> None:
        self.url = url
        self.spool = spool
        self._key = key.encode()
        self._context = context
        self._timeout = timeout
        self._sleep = sleep
        self._clock = clock
        self._random = random

    async def send(self, bundle: Bundle) -> None:
        await asyncio.to_thread(self.spool.push, bundle)
        await self.flush()

    async def flush(self) -> None:
        """Deliver everything in the spool, oldest first; stop at the first bundle that won't go."""
        rejected: SinkError | None = None
        for path, bundle in await asyncio.to_thread(lambda: list(self.spool.pending())):
            try:
                await self._deliver(bundle)
            except SinkError as e:
                if not _permanent(e):
                    raise
                log.error("webhook rejected bundle %s, dropping it: %s", bundle["id"], e)
                rejected = SinkError(f"webhook rejected bundle {bundle['id']}: {e}", e.status)
            await asyncio.to_thread(self.spool.ack, path)
        if rejected:
            raise rejected

    async def _deliver(self, bundle: Bundle) -> None:
        start, attempt = self._clock(), 0
        while True:
            try:
                await asyncio.to_thread(self._post, bundle)
                return
            except SinkError as e:
                if _permanent(e):
                    raise
                err: Exception = e
            except TRANSIENT as e:
                err = e
            elapsed = self._clock() - start
            if elapsed >= RETRY_FOR:
                raise SinkError(
                    f"webhook: giving up on {bundle['id']} after {elapsed:.0f}s,"
                    f" left spooled: {err}"
                ) from err
            delay = min(MAX_DELAY, 2.0**attempt) * self._random(0.5, 1.0)
            attempt += 1
            log.info("webhook: %s; retry in %.1fs", err, delay)
            await self._sleep(min(delay, RETRY_FOR - elapsed))

    def _post(self, bundle: Bundle) -> None:
        body = encode(bundle)
        ts = str(int(time.time()))
        sig = hmac.new(self._key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-Sentry-V2-Timestamp": ts,
            "X-Sentry-V2-Signature": f"sha256={sig}",
        }
        post(self.url, body, headers, self._context, self._timeout)
