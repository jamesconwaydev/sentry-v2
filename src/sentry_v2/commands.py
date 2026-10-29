"""Control socket commands. The CLI and Cockpit consume exactly these shapes.

=========  ==========================  ==============================================
cmd        args                        result
=========  ==========================  ==============================================
status     -                           {version, mode, paused, uptime_s,
                                       collectors: {name: health},
                                       active_actions: [record], breaker: {open,
                                       until, failures}, sinks: {failures: {sink: n},
                                       dropped: {sink: n}}, last_reload_error,
                                       events_dropped: {collector: n},
                                       held: [{unit, since}]}
psi        -                           {cgroups: [{cgroup, resource, kind, avg10,
                                       avg60, avg300}]}
incidents  since?: RFC 3339, unit?,    {incidents: [{id, ts, severity, kind, target,
           limit?: int = 50            policy}]}, newest first
show       id: UUID                    {bundle: <sentry-v2/bundle/1 document>}
actions    -                           {active: [record], recent: [record]} (recent:
                                       last 100, newest first)
rollback   id?: str, all?: bool        {rolled_back: [record]}
ack        unit: str                   {acknowledged: unit}
pause      -                           {paused: true}
resume     -                           {paused: false}
reload     -                           {reloaded: true}
restore    backup_id: <unit>/<ts>      {restored: [path], skipped: [path], note: str}
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

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from . import __version__, actions
from .control import CommandError, Handler
from .executor import ACTION_KIND
from .policy import AvcWhen, PsiWhen, effective_mode
from .state import ActionRecord

if TYPE_CHECKING:
    from .daemon import Daemon

_BACKUP_ID = re.compile(r"([A-Za-z0-9:_.@\\-]+)/(\d{8}T\d{6}Z)")
_TYPE_NAMES = {str: "a string", int: "an integer", bool: "true or false"}
# The unit directories the service may write (ReadWritePaths in the unit).
# Anything else, a package's unit under /usr/lib among them, is read-only.
RESTORE_ROOTS = (Path("/etc/systemd/system"), Path("/run/systemd/system"))


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


def _check_private(path: Path) -> None:
    """Refuse a backup directory someone other than us could have planted files in."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        raise CommandError("no such backup") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
        raise CommandError(f"{path}: must be a directory owned by root, writable only by it")


def _open_dir(path: Path) -> int:
    """Open `path` under its restore root without following a symlink below the root.

    Missing directories (a drop-in directory removed since the backup) are
    created 0755, whatever the umask. The caller closes the returned fd.
    """
    root = next(r for r in RESTORE_ROOTS if path.is_relative_to(r))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.relative_to(root).parts:
            created = True
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                created = False
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            if created:
                os.fchmod(fd, 0o755)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _stage(dir_fd: int, name: str, data: bytes, src: Path) -> None:
    """Write `data` to a new `name` in `dir_fd`, with the mode and times of `src`."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(name, dir_fd=dir_fd)  # a leftover from an interrupted restore
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=dir_fd), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
        actions.copy_mode_and_times(src, f.fileno())


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
            "ack": self.ack,
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
            "held": [{"unit": u, "since": t} for u, t in d.executor.held().items()],
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

    async def ack(self, args: dict[str, Any]) -> dict[str, Any]:
        unit = _required(args, "unit", str)
        if not await self.d.executor.ack(unit):
            raise CommandError(f"{unit} is not held")
        return {"acknowledged": unit}

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
        """Put backed-up unit files back after checking every hash in the manifest.

        The pre-flight refuses before anything is written: files that still
        match the backup are skipped, and a changed file outside
        RESTORE_ROOTS refuses the whole restore. Every file is then staged
        next to its destination, so a failure there (a full disk, a symlinked
        directory) restores nothing. Only a rename failing after that can
        leave a partial restore; the error lists what was restored.
        """
        backup_id = _required(args, "backup_id", str)
        m = _BACKUP_ID.fullmatch(backup_id)
        if m is None or m.group(1) in (".", ".."):
            raise CommandError("backup_id must look like <unit>/<YYYYmmddTHHMMSSZ>")
        backups = self.d.executor.backups_dir
        bdir = backups / backup_id
        for d in (backups, bdir.parent, bdir):
            _check_private(d)
        try:
            manifest = (bdir / "MANIFEST.sha256").read_text()
        except FileNotFoundError:
            raise CommandError("no such backup") from None
        copies: list[tuple[Path, bytes, Path]] = []
        skipped: list[str] = []
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
            dest = Path("/", *parts[1:])
            try:
                unchanged = hashlib.sha256(dest.read_bytes()).hexdigest() == digest
            except FileNotFoundError:
                unchanged = False
            except OSError as e:
                raise CommandError(f"{dest}: {e.strerror}") from None
            if unchanged:
                skipped.append(str(dest))
            else:
                copies.append((src, data, dest))
        if outside := [str(d) for _, _, d in copies if not _restorable(d)]:
            raise CommandError(
                "nothing restored: changed since the backup and outside "
                f"{' and '.join(map(str, RESTORE_ROOTS))}, where sentry-v2 cannot "
                f"write: {', '.join(outside)}. Copy them back by hand from "
                f"{bdir}/files and run the restore again."
            )
        staged: list[tuple[int, str, Path]] = []
        restored: list[str] = []
        try:
            for src, data, dest in copies:
                try:
                    dir_fd = _open_dir(dest.parent)
                    staged.append((dir_fd, f".{dest.name}.sentry-v2-restore", dest))
                    # the bytes that were verified, not whatever the file holds now
                    _stage(dir_fd, staged[-1][1], data, src)
                except OSError as e:
                    _unstage(staged)
                    raise CommandError(f"nothing restored: staging {dest} failed ({e})") from None
            for i, (dir_fd, tmp, dest) in enumerate(staged):
                try:
                    os.replace(tmp, dest.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                except OSError as e:
                    _unstage(staged[i:])
                    msg = f"restoring {dest} failed ({e}); restored {restored}"
                    raise CommandError(msg) from None
                restored.append(str(dest))
        finally:
            for dir_fd, _, _ in staged:
                os.close(dir_fd)
        if restored:
            note = f"run systemctl daemon-reload && systemctl reload {m.group(1)}"
        else:
            note = "every file already matches the backup; nothing to do"
        return {"restored": restored, "skipped": skipped, "note": note}

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


def _unstage(staged: list[tuple[int, str, Path]]) -> None:
    for dir_fd, tmp, _ in staged:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)


def _restorable(path: Path) -> bool:
    return any(path.is_relative_to(root) for root in RESTORE_ROOTS)


def _signal(when: object) -> str:
    if isinstance(when, PsiWhen):
        return "psi"
    return "avc" if isinstance(when, AvcWhen) else "unit_failed"
