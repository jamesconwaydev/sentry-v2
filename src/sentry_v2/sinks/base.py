"""What every sink shares: the protocol, the error type, bundle encoding and secret loading."""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Protocol

Bundle = dict[str, Any]


class SinkError(Exception):
    """A delivery failed. `status` is the HTTP status when there was one."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class Sink(Protocol):
    name: str

    async def send(self, bundle: Bundle) -> None: ...


def encode(bundle: Bundle) -> bytes:
    return json.dumps(bundle, separators=(",", ":")).encode()


def bundle_filename(bundle: Bundle) -> str:
    """`<id>.json`, with the id parsed as a UUID so it can never escape a directory."""
    return f"{uuid.UUID(bundle['id'])}.json"


def load_secret(path: Path, *, check_owner: bool = True) -> str:
    """Read a secret from a root-owned file nobody else can read.

    A relative path names a systemd credential (LoadCredential=) and is looked
    up in $CREDENTIALS_DIRECTORY.
    """
    if not path.is_absolute():
        creds = os.environ.get("CREDENTIALS_DIRECTORY")
        if not creds:
            raise SinkError(f"secret {path}: relative path but CREDENTIALS_DIRECTORY is not set")
        path = Path(creds) / path
    try:
        # One open, checks on the fd: nothing can swap the file in between.
        # O_NONBLOCK so a FIFO fails the regular-file check instead of hanging.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SinkError(f"secret {path}: not a regular file")
            if st.st_mode & 0o077:
                mode = stat.S_IMODE(st.st_mode)
                raise SinkError(f"secret {path}: mode {mode:04o} is readable by others; chmod 0600")
            if check_owner and st.st_uid != 0:
                raise SinkError(f"secret {path}: must be owned by root (uid {st.st_uid})")
            value = os.read(fd, 64 * 1024).decode().rstrip("\r\n")  # secrets are small
        finally:
            os.close(fd)
    except OSError as e:
        raise SinkError(f"cannot read secret {path}: {e.strerror}") from e
    except UnicodeDecodeError as e:
        raise SinkError(f"secret {path}: not UTF-8") from e
    if not value:
        raise SinkError(f"secret {path}: file is empty")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise SinkError(f"secret {path}: contains a control character")
    return value
