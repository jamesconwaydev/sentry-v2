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
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise SinkError(f"secret {path}: not a regular file")
        if st.st_mode & 0o077:
            mode = stat.S_IMODE(st.st_mode)
            raise SinkError(f"secret {path}: mode {mode:04o} is readable by others; chmod 0600")
        if check_owner and st.st_uid != 0:
            raise SinkError(f"secret {path}: must be owned by root (uid {st.st_uid})")
        value = path.read_text().rstrip("\r\n")
    except OSError as e:
        raise SinkError(f"cannot read secret {path}: {e.strerror}") from e
    if not value:
        raise SinkError(f"secret {path}: file is empty")
    return value
