"""Action records and the append-only journal that makes them crash-safe.

Every enforced action is written as `planned` (with the values it will
restore) before systemd is touched, so a crash at any point leaves enough
on disk for startup replay to undo it.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .policy import Mode

log = logging.getLogger(__name__)

Status = Literal["planned", "applied", "rolled_back", "failed", "rollback_failed", "dry_run"]
ActionKind = Literal["throttle", "freeze", "backup_reload", "notify"]
REVERSIBLE: frozenset[str] = frozenset({"throttle", "freeze"})


@dataclass(frozen=True)
class ActionRecord:
    """One action's state. The journal keeps every transition; the last one wins.

    `mode` is the mode actually used (forced to dry-run by pause or the
    breaker); `configured_mode` is what the policy asked for. `previous`
    holds raw systemd values captured before apply; `params` what was (or
    would be) written.
    """

    id: str
    policy: str
    action: ActionKind
    target: str
    mode: Mode
    status: Status
    previous: dict[str, Any]
    applied_at: float | None
    expires_at: float | None
    error: str | None
    incident_id: str
    configured_mode: Mode = "dry-run"
    params: dict[str, Any] = field(default_factory=dict)
    backup_id: str | None = None

    @property
    def is_open(self) -> bool:
        """Still needs a rollback (or, if only planned, a decision at replay)."""
        if self.status == "planned":
            return self.action != "notify"
        return self.status == "applied" and self.action in REVERSIBLE


_FIELDS = frozenset(f.name for f in dataclasses.fields(ActionRecord))


class ActionJournal:
    """`actions.jsonl`: one JSON object per transition, fsynced on every append."""

    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self._clock = clock
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.exists():
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
            _fsync_dir(path.parent)  # so the new file's entry survives a crash

    def append(self, rec: ActionRecord) -> None:
        """Write `rec` as one line stamped with wall time `ts`, durably."""
        line = json.dumps({**dataclasses.asdict(rec), "ts": self._clock()}) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self) -> dict[str, tuple[ActionRecord, float]]:
        """Last (record, ts) per id. A partial final line from a crash is cut off."""
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return {}
        end = data.rfind(b"\n") + 1
        if end < len(data):
            log.warning("%s: dropping truncated last line %r", self.path, data[end:][:200])
            with self.path.open("r+b") as f:
                f.truncate(end)
                os.fsync(f.fileno())
        out: dict[str, tuple[ActionRecord, float]] = {}
        for n, line in enumerate(data[:end].splitlines(), 1):
            try:
                obj = json.loads(line)
                ts = float(obj["ts"])
                rec = ActionRecord(**{k: v for k, v in obj.items() if k in _FIELDS})
            except (ValueError, KeyError, TypeError) as e:
                log.error("%s:%d: skipping unreadable record: %s", self.path, n, e)
                continue
            out[rec.id] = (rec, ts)
        return out

    def load(self) -> dict[str, ActionRecord]:
        """The latest record for every id."""
        return {k: rec for k, (rec, _ts) in self._read().items()}

    def compact(self, older_than: float, now: float) -> None:
        """Drop closed records last touched before `now - older_than`; atomic rewrite.

        `rollback_failed` records are kept at any age: they stay open until
        an operator clears them.
        """
        keep = [
            (rec, ts)
            for rec, ts in self._read().values()
            if rec.is_open or rec.status == "rollback_failed" or ts >= now - older_than
        ]
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            for rec, ts in keep:
                os.write(fd, (json.dumps({**dataclasses.asdict(rec), "ts": ts}) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        _fsync_dir(self.path.parent)


class HoldList:
    """`held.json`: units held after acting too often, until someone acknowledges them.

    Small and rewritten whole on every change, atomically.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.units: dict[str, float] = {}  # unit -> wall time it was held

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
            self.units = {str(u): float(t) for u, t in raw.items()}
        except FileNotFoundError:
            self.units = {}
        except (OSError, ValueError, TypeError, AttributeError) as e:
            log.error("%s: unreadable, starting with no held units: %s", self.path, e)
            self.units = {}

    def save(self) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(self.units).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        _fsync_dir(self.path.parent)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
