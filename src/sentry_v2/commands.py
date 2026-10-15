"""Control socket commands. The CLI and Cockpit consume exactly these shapes.

=========  ==========================  ==============================================
cmd        args                        result
=========  ==========================  ==============================================
status     -                           {version, mode, paused, uptime_s,
                                       collectors: {name: health},
                                       active_actions: [record], breaker: {open,
                                       until, failures}, sinks: {failures: {sink: n},
                                       dropped: {sink: n}}, last_reload_error,
                                       events_dropped: {collector: n}}
psi        -                           {cgroups: [{cgroup, resource, kind, avg10,
                                       avg60, avg300}]}
incidents  since?: RFC 3339, unit?,    {incidents: [{id, ts, severity, kind, target,
           limit?: int = 50            policy}]}, newest first
show       id: UUID                    {bundle: <sentry-v2/bundle/1 document>}
actions    -                           {active: [record], recent: [record]} (recent:
                                       last 100, newest first)
rollback   id?: str, all?: bool        {rolled_back: [record]}
pause      -                           {paused: true}
resume     -                           {paused: false}
reload     -                           {reloaded: true}
restore    backup_id: <unit>/<ts>      {restored: [path], note: str}
policies   -                           {policies: [{name, mode, effective_mode,
                                       signal, actions: [kind], source}],
                                       last_reload_error}
subscribe  -                           {subscribed: true}, then {"event": {"type":
                                       "incident", "incident": <summary>}} and
                                       {"event": {"type": "action", "record":
                                       <record>}} lines (served by ControlServer)
=========  ==========================  ==============================================

A record is ActionRecord's fields plus `ts`, the wall time of its latest
transition. Errors come back as ok:false with the CommandError text.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from . import __version__
from .control import CommandError, Handler
from .executor import ACTION_KIND
from .policy import AvcWhen, PsiWhen, effective_mode
from .state import ActionRecord

if TYPE_CHECKING:
    from .daemon import Daemon

_BACKUP_ID = re.compile(r"([A-Za-z0-9:_.@\\-]+)/(\d{8}T\d{6}Z)")
_TYPE_NAMES = {str: "a string", int: "an integer", bool: "true or false"}


def _arg[T](args: dict[str, Any], name: str, kind: type[T], default: T | None = None) -> T | None:
    value = args.get(name)
    if value is None:
        return default
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise CommandError(f"{name} must be {_TYPE_NAMES[kind]}")
    return value


def _required[T](args: dict[str, Any], name: str, kind: type[T]) -> T:
    value = _arg(args, name, kind)
    if value is None:
        raise CommandError(f"{name} is required")
    return value


def _parse_ts(text: str) -> dt.datetime:
    ts = dt.datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.UTC)


class Commands:
    def __init__(self, daemon: Daemon) -> None:
        self.d = daemon

    def handlers(self) -> dict[str, Handler]:
        return {
            "status": self.status,
            "psi": self.psi,
            "incidents": self.incidents,
            "show": self.show,
            "actions": self.actions,
            "rollback": self.rollback,
            "pause": self.pause,
            "resume": self.resume,
            "reload": self.reload,
            "restore": self.restore,
            "policies": self.policies,
        }

    def _records(self, records: list[ActionRecord]) -> list[dict[str, Any]]:
        return [self.d.record_dict(r) for r in records]

    async def status(self, args: dict[str, Any]) -> dict[str, Any]:
        d = self.d
        return {
            "version": __version__,
            "mode": d.cfg.daemon.mode,
            "paused": d.paused,
            "uptime_s": round(d.uptime(), 3),
            "collectors": d.collector_health(),
            "active_actions": self._records(d.executor.active()),
            "breaker": d.executor.breaker_state(),
            "sinks": {"failures": dict(d.sinks.failures), "dropped": dict(d.sinks.dropped)},
            "last_reload_error": d.last_reload_error,
            "events_dropped": dict(d.queue.dropped),
        }

    async def psi(self, args: dict[str, Any]) -> dict[str, Any]:
        rows = [
            {"cgroup": cg, "resource": res, "kind": kind,
             "avg10": ev.avg10, "avg60": ev.avg60, "avg300": ev.avg300}
            for (cg, res, kind), ev in sorted(self.d.samples.items())
        ]  # fmt: skip
        return {"cgroups": rows}

    async def incidents(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = _arg(args, "limit", int, 50)
        if limit is None or limit < 1:
            raise CommandError("limit must be a positive integer")
        unit = _arg(args, "unit", str)
        since = None
        if (text := _arg(args, "since", str)) is not None:
            try:
                since = _parse_ts(text)
            except ValueError:
                raise CommandError("since must be an RFC 3339 timestamp") from None
        out: list[dict[str, Any]] = []
        for s in self.d.incidents:  # newest first
            if len(out) >= limit:
                break
            target = s["target"] or ""
            if unit is not None and unit not in (target, target.rsplit("/", 1)[-1]):
                continue
            if since is not None and _parse_ts(s["ts"]) < since:
                continue
            out.append(s)
        return {"incidents": out}

    async def show(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            bundle_id = uuid.UUID(_required(args, "id", str))
        except ValueError:
            raise CommandError("id must be a UUID") from None
        root = self.d.cfg.sinks.file.dir
        for path in root.glob(f"*/*/*/{bundle_id}.json"):
            return {"bundle": json.loads(path.read_text())}
        raise CommandError("no such bundle")

    async def actions(self, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "active": self._records(self.d.executor.active()),
            "recent": list(reversed(self.d.recent.values())),
        }

    async def rollback(self, args: dict[str, Any]) -> dict[str, Any]:
        rec_id = _arg(args, "id", str)
        if rec_id is not None:
            done = await self.d.executor.rollback(rec_id)
            if not done:
                raise CommandError("no such action")
        elif _arg(args, "all", bool):
            done = await self.d.executor.rollback(None)
        else:
            raise CommandError("give id or all")
        return {"rolled_back": self._records(done)}

    async def pause(self, args: dict[str, Any]) -> dict[str, Any]:
        self.d.paused = True
        self.d.executor.pause()
        return {"paused": True}

    async def resume(self, args: dict[str, Any]) -> dict[str, Any]:
        self.d.paused = False
        self.d.executor.resume()
        return {"paused": False}

    async def reload(self, args: dict[str, Any]) -> dict[str, Any]:
        if error := await self.d.reload():
            raise CommandError(error)
        return {"reloaded": True}

    async def restore(self, args: dict[str, Any]) -> dict[str, Any]:
        """Put backed-up unit files back after checking every hash in the manifest."""
        backup_id = _required(args, "backup_id", str)
        m = _BACKUP_ID.fullmatch(backup_id)
        if m is None or m.group(1) in (".", ".."):
            raise CommandError("backup_id must look like <unit>/<YYYYmmddTHHMMSSZ>")
        bdir = self.d.executor.backups_dir / backup_id
        try:
            manifest = (bdir / "MANIFEST.sha256").read_text()
        except FileNotFoundError:
            raise CommandError("no such backup") from None
        copies: list[tuple[Path, Path]] = []
        for line in manifest.splitlines():
            digest, _, rel = line.partition("  ")
            parts = PurePosixPath(rel).parts
            if len(parts) < 2 or parts[0] != "files" or ".." in parts:
                raise CommandError("manifest is malformed")
            src = bdir / rel
            try:
                data = src.read_bytes()
            except OSError as e:
                raise CommandError(f"{rel}: {e.strerror}") from None
            if hashlib.sha256(data).hexdigest() != digest:
                raise CommandError(f"{rel}: checksum mismatch")
            copies.append((src, Path("/", *parts[1:])))
        restored: list[str] = []
        for src, dest in copies:
            tmp = dest.with_name(f".{dest.name}.sentry-v2-restore")
            try:
                shutil.copy2(src, tmp)
                os.replace(tmp, dest)
            except OSError as e:
                raise CommandError(f"restoring {dest} failed ({e}); restored {restored}") from None
            restored.append(str(dest))
        unit = m.group(1)
        note = f"run systemctl daemon-reload && systemctl reload {unit}"
        return {"restored": restored, "note": note}

    async def policies(self, args: dict[str, Any]) -> dict[str, Any]:
        mode = self.d.cfg.daemon.mode
        rows = [
            {
                "name": p.name,
                "mode": p.mode,
                "effective_mode": effective_mode(mode, p.mode),
                "signal": _signal(p.when),
                "actions": [ACTION_KIND[type(a)] for a in p.actions],
                "source": str(p.source),
            }
            for p in self.d.cfg.policies
        ]
        return {"policies": rows, "last_reload_error": self.d.last_reload_error}


def _signal(when: object) -> str:
    if isinstance(when, PsiWhen):
        return "psi"
    return "avc" if isinstance(when, AvcWhen) else "unit_failed"
