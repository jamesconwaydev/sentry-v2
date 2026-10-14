"""RFC 5424 syslog over UDP, TCP or TLS, the bundle as JSON in MSG."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from typing import Literal

from .base import Bundle

SD_ID = "sentry-v2@32473"
FACILITY_DAEMON = 3
SEVERITY = {"critical": 2, "warning": 4, "info": 6}
UDP_MAX = 8192

Transport = Literal["udp", "tcp", "tls"]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_message(
    bundle: Bundle, hostname: str, app_name: str, max_len: int | None = None
) -> bytes:
    """One RFC 5424 message. With `max_len`, MSG is cut to fit and the SD says truncated="1"."""
    params = {
        "id": bundle["id"],
        "severity": bundle["severity"],
        "policy": (bundle.get("decision") or {}).get("policy"),
        "unit": (bundle.get("incident") or {}).get("target"),
    }
    msg = json.dumps(bundle, separators=(",", ":")).encode()  # ASCII: no BOM needed

    def head(extra: dict[str, str]) -> bytes:
        sd = "".join(
            f' {k}="{_escape(str(v))}"' for k, v in (params | extra).items() if v is not None
        )
        pri = FACILITY_DAEMON * 8 + SEVERITY.get(bundle["severity"], 5)
        return f"<{pri}>1 {bundle['ts']} {hostname} {app_name} - BUNDLE [{SD_ID}{sd}] ".encode()

    line = head({}) + msg
    if max_len is not None and len(line) > max_len:
        h = head({"truncated": "1"})
        line = h + msg[: max_len - len(h)]
    return line


class SyslogSink:
    name = "syslog"

    def __init__(
        self,
        host: str,
        port: int,
        transport: Transport,
        context: ssl.SSLContext | None = None,
        hostname: str | None = None,
        app_name: str = "sentry-v2",
        timeout: float = 10.0,
    ) -> None:
        if transport == "tls" and context is None:
            raise ValueError("tls transport needs an SSL context")
        self.host = host
        self.port = port
        self.transport = transport
        self._context = context
        self._hostname = hostname or socket.gethostname() or "-"
        self._app_name = app_name
        self._timeout = timeout

    async def send(self, bundle: Bundle) -> None:
        await asyncio.to_thread(self._send, bundle)

    def _send(self, bundle: Bundle) -> None:
        if self.transport == "udp":
            line = format_message(bundle, self._hostname, self._app_name, UDP_MAX)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(line, (self.host, self.port))
            return
        line = format_message(bundle, self._hostname, self._app_name)
        frame = f"{len(line)} ".encode() + line  # RFC 6587 octet counting
        # ponytail: a connection per bundle; bundles are rare, keep one open if that changes
        with socket.create_connection((self.host, self.port), timeout=self._timeout) as raw:
            if self._context is not None:
                with self._context.wrap_socket(raw, server_hostname=self.host) as tls:
                    tls.sendall(frame)
            else:
                raw.sendall(frame)
