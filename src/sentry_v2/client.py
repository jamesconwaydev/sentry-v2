"""Synchronous client for the control socket (newline-delimited JSON)."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class ControlError(Exception):
    """The daemon answered ok:false; the message is its error text."""


class NotRunning(Exception):
    pass


class PermissionDenied(Exception):
    pass


class ControlClient:
    def __init__(self, path: Path, timeout: float = 10.0) -> None:
        self.path = path
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(str(self.path))
        except (FileNotFoundError, ConnectionRefusedError, NotADirectoryError):
            s.close()
            raise NotRunning(f"sentry-v2 is not running (no socket at {self.path})") from None
        except PermissionError:
            s.close()
            raise PermissionDenied(
                f"permission denied on {self.path}; join the sentry-v2 group "
                "(sentry-v2-admin to change anything) and log in again"
            ) from None
        return s

    def call(self, cmd: str, **args: Any) -> dict[str, Any]:
        with self._connect() as s:
            s.sendall(json.dumps({"id": 1, "cmd": cmd, "args": args}).encode() + b"\n")
            line = s.makefile("rb").readline()
        if not line:
            raise ControlError("the daemon closed the connection without answering")
        resp = json.loads(line)
        if not resp.get("ok"):
            raise ControlError(str(resp.get("error", "unknown error")))
        result: dict[str, Any] = resp["result"]
        return result

    def subscribe(self) -> Iterator[dict[str, Any]]:
        """Yield event dicts until the daemon disconnects."""
        with self._connect() as s:
            s.sendall(json.dumps({"id": 1, "cmd": "subscribe", "args": {}}).encode() + b"\n")
            s.settimeout(None)
            for line in s.makefile("rb"):
                msg = json.loads(line)
                if "event" in msg:
                    yield msg["event"]
                elif msg.get("ok") is False:
                    raise ControlError(str(msg.get("error", "unknown error")))
