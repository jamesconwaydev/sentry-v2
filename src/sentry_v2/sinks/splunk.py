"""Splunk HTTP Event Collector."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import ssl
from typing import Any

from .base import Bundle
from .http import post

ENDPOINT = "/services/collector/event"


class SplunkHecSink:
    name = "splunk_hec"

    def __init__(
        self,
        url: str,
        token: str,
        index: str | None,
        context: ssl.SSLContext,
        timeout: float = 10.0,
    ) -> None:
        url = url.rstrip("/")
        self.url = url if url.endswith(ENDPOINT) else url + ENDPOINT
        self.index = index
        self._token = token
        self._context = context
        self._timeout = timeout

    async def send(self, bundle: Bundle) -> None:
        event: dict[str, Any] = {
            "event": bundle,
            "sourcetype": "sentry-v2:bundle",
            "time": dt.datetime.fromisoformat(bundle["ts"]).timestamp(),
        }
        if self.index:
            event["index"] = self.index
        headers = {"Authorization": f"Splunk {self._token}", "Content-Type": "application/json"}
        body = json.dumps(event, separators=(",", ":")).encode()
        await asyncio.to_thread(post, self.url, body, headers, self._context, self._timeout)
