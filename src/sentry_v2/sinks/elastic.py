"""Elasticsearch `_bulk` create into an index or data stream."""

from __future__ import annotations

import asyncio
import base64
import json
import ssl

from .base import Bundle, SinkError, encode
from .http import post


class ElasticSink:
    name = "elastic"

    def __init__(
        self,
        url: str,
        index: str,
        auth: str,
        context: ssl.SSLContext,
        timeout: float = 10.0,
    ) -> None:
        """`auth` is the whole Authorization header value: see `api_key` and `basic`."""
        url = url.rstrip("/")
        self.url = url if url.endswith("/_bulk") else url + "/_bulk"
        self.index = index
        self._auth = auth
        self._context = context
        self._timeout = timeout

    @staticmethod
    def api_key(key: str) -> str:
        return f"ApiKey {key}"

    @staticmethod
    def basic(username: str, password: str) -> str:
        return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    async def send(self, bundle: Bundle) -> None:
        action = encode({"create": {"_index": self.index, "_id": bundle["id"]}})
        doc = encode({**bundle, "@timestamp": bundle["ts"]})  # data streams require @timestamp
        headers = {"Authorization": self._auth, "Content-Type": "application/x-ndjson"}
        _, reply = await asyncio.to_thread(
            post, self.url, action + b"\n" + doc + b"\n", headers, self._context, self._timeout
        )
        result = json.loads(reply)
        if result.get("errors"):
            item = result["items"][0]["create"]
            if item["status"] == 409:  # same _id already indexed: a resend that got through
                return
            error = item.get("error")
            raise SinkError(f"elastic rejected bundle {bundle['id']}: {error}", item["status"])
