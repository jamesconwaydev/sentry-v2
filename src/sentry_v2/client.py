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


def _is_one(v: object) -> bool:
    return v == 1 and not isinstance(v, bool)


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

    @staticmethod
    def _request(cmd: str, args: dict[str, Any]) -> bytes:
        return json.dumps({"id": 1, "cmd": cmd, "args": args}).encode() + b"\n"

    @staticmethod
    def _parse(line: bytes) -> dict[str, Any]:
        """One complete reply line, or ControlError."""
        if not line.endswith(b"\n"):
            raise ControlError("daemon did not answer: the reply was cut short")
        try:
            resp = json.loads(line)
        except ValueError as e:
            raise ControlError(f"daemon did not answer: bad reply ({e})") from None
        if not isinstance(resp, dict):
            raise ControlError("daemon did not answer: reply is not a JSON object")
        return resp

    def call(self, cmd: str, **args: Any) -> dict[str, Any]:
        with self._connect() as s:
            try:
                s.sendall(self._request(cmd, args))
                with s.makefile("rb") as f:
                    resp = self._parse(f.readline())
            except OSError as e:  # includes timeouts
                raise ControlError(f"daemon did not answer: {e}") from None
        if not resp.get("ok"):
            raise ControlError(str(resp.get("error", "unknown error")))
        if not _is_one(resp.get("id")):
            raise ControlError("daemon did not answer: reply id does not match the request")
        result: dict[str, Any] = resp["result"]
        return result

    def subscribe(self) -> Iterator[dict[str, Any]]:
        """Yield event dicts until the daemon disconnects."""
        with self._connect() as s:
            try:
                s.sendall(self._request("subscribe", {}))
                with s.makefile("rb") as f:
                    ack = self._parse(f.readline())  # still under the connect timeout
                    if not ack.get("ok"):
                        raise ControlError(str(ack.get("error", "unknown error")))
                    if not _is_one(ack.get("id")):
                        raise ControlError("daemon did not answer: ack id does not match")
                    s.settimeout(None)
                    for line in f:
                        msg = self._parse(line)
                        if "event" in msg:
                            yield msg["event"]
                        elif msg.get("ok") is False:
                            raise ControlError(str(msg.get("error", "unknown error")))
            except OSError as e:
                raise ControlError(f"daemon did not answer: {e}") from None
