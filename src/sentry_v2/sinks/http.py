"""Blocking HTTPS POST for the HTTP sinks; callers run it via asyncio.to_thread."""

from __future__ import annotations

import http.client
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from .base import SinkError

# Connection failures that are worth retrying, alongside a 5xx SinkError.
TRANSIENT = (OSError, http.client.HTTPException)


def tls_context(ca_file: Path | None) -> ssl.SSLContext:
    """Verifying client context, TLS 1.2 or later, optionally trusting a private CA."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def post(
    url: str, body: bytes, headers: dict[str, str], context: ssl.SSLContext, timeout: float
) -> tuple[int, bytes]:
    """POST `body` to an https URL; return (status, response body). Non-2xx raises SinkError."""
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise SinkError(f"not an https URL: {url}")
    conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=context)
    try:
        target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        conn.request("POST", target, body, headers)
        resp = conn.getresponse()
        data = resp.read()
    finally:
        conn.close()
    if not 200 <= resp.status < 300:
        raise SinkError(f"POST {u.hostname}{u.path}: HTTP {resp.status}", resp.status)
    return resp.status, data
