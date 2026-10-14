"""UUIDv7 generation (RFC 9562)."""

from __future__ import annotations

import secrets
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms = 0
_counter = 0


def uuid7() -> str:
    """Return a UUIDv7 string that sorts after every earlier one from this process.

    The 12-bit rand_a field is a counter within a millisecond; if it
    overflows, the timestamp is advanced by one millisecond.
    """
    global _last_ms, _counter
    with _lock:
        ms = time.time_ns() // 1_000_000
        if ms > _last_ms:
            _last_ms = ms
            _counter = secrets.randbelow(0x200)  # headroom so a busy millisecond rarely overflows
        else:
            _counter += 1
            if _counter > 0xFFF:
                _last_ms += 1
                _counter = 0
        ms_now, counter = _last_ms, _counter
    value = (ms_now & 0xFFFFFFFFFFFF) << 80
    value |= 0x7 << 76
    value |= counter << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return str(uuid.UUID(int=value))
