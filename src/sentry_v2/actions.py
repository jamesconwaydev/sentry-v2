"""How each action kind is captured, applied and undone against systemd.

The executor decides when; this module only knows what. Capture (`prepare`)
is separate from `apply` so the previous values can be journalled in
between.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any

from .cgroupfs import CgroupFS
from .policy import ActionSpec, BackupReload, Freeze, Notify, Throttle
from .state import ActionRecord
from .systemd import SystemdError, SystemdManager, UnitNotFound
from .units import Percent

MEMORY_HIGH_FLOOR = 32 * 1024**2
UNIT_INACTIVE = "org.freedesktop.systemd1.UnitInactive"


class Refused(Exception):
    """The action must not go ahead; the message is the record's error."""


async def prepare(
    spec: ActionSpec, unit: str, mgr: SystemdManager, fs: CgroupFS
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read current state; return (previous values to restore, params to apply)."""
    props = await mgr.get_properties(unit)
    match spec:
        case Throttle():
            mh = spec.memory_high
            if isinstance(mh, Percent):
                mh = max(mh.of(fs.memory_current(props.cgroup)), MEMORY_HIGH_FLOOR)
            previous: dict[str, Any] = {}
            if mh is not None:
                previous["memory_high"] = props.memory_high
            if spec.cpu_weight is not None:
                previous["cpu_weight"] = props.cpu_weight
            return previous, {"memory_high": mh, "cpu_weight": spec.cpu_weight}
        case Freeze():
            if props.active_state != "active":
                raise Refused("unit inactive")
            if props.freezer_state != "running":
                raise Refused(f"already {props.freezer_state}")
            return {"freezer_state": props.freezer_state}, {"cgroup": props.cgroup}
        case BackupReload():
            files = [props.fragment_path, *props.drop_in_paths, *map(str, spec.paths)]
            return {}, {"files": [f for f in files if f]}
        case Notify():  # pragma: no cover - the executor never prepares a notify
            return {}, {}


def describe(spec: ActionSpec) -> dict[str, Any]:
    """What a dry-run would write, without touching systemd (a Percent stays "90%")."""
    if not isinstance(spec, Throttle):
        return {}
    mh = spec.memory_high
    return {
        "memory_high": f"{mh.value:g}%" if isinstance(mh, Percent) else mh,
        "cpu_weight": spec.cpu_weight,
    }


def copy_mode_and_times(src: Path | str, dest: Path | str) -> None:
    """Give `dest` the permission bits and times of `src`, but not its xattrs.

    shutil.copystat (and copy2) also copies security.selinux. That would
    label a backup as a unit file, or a restored unit file as sentry-v2
    state, and the daemon's SELinux domain is not allowed to relabel.
    """
    st = os.stat(src)
    os.chmod(dest, stat.S_IMODE(st.st_mode))
    os.utime(dest, ns=(st.st_atime_ns, st.st_mtime_ns))


def backup(unit: str, files: list[str], backups_dir: Path, now: float) -> str:
    """Copy `files` under `backups_dir/<unit>/<ts>/files/<abs path>` with a sha256 manifest.

    Returns the backup id `<unit>/<ts>`. Copies keep mode and mtime.
    """
    backup_id = f"{unit}/{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}"
    bdir = backups_dir / backup_id
    copies = [(src, Path("files") / Path(src).relative_to("/")) for src in files]
    for src, rel in copies:
        if not (bdir / rel).resolve().is_relative_to(bdir.resolve()):
            raise ValueError(f"{src}: escapes the backup directory")
    backups_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    bdir.parent.mkdir(mode=0o700, exist_ok=True)
    bdir.mkdir(mode=0o700)
    manifest = []
    for src, rel in copies:
        dest = bdir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        copy_mode_and_times(src, dest)
        manifest.append(f"{hashlib.sha256(dest.read_bytes()).hexdigest()}  {rel}\n")
    (bdir / "MANIFEST.sha256").write_text("".join(manifest))
    return backup_id


async def apply(spec: ActionSpec, unit: str, params: dict[str, Any], mgr: SystemdManager) -> None:
    """The D-Bus call that makes the action take effect."""
    match spec:
        case Throttle():
            await mgr.set_properties(unit, params["memory_high"], params["cpu_weight"])
        case Freeze():
            await mgr.freeze(unit)
        case BackupReload():
            await mgr.reload(unit)
        case Notify():  # pragma: no cover - nothing to apply
            pass


CHANGED_SINCE = "changed since; left as is"


async def rollback(rec: ActionRecord, mgr: SystemdManager) -> str | None:
    """Undo `rec`. Returns a note when there was nothing (or nothing safe) to undo.

    A throttle is restored only while every value it wrote is still in
    place; if someone changed one since, their change wins and nothing is
    written. Raises on failure.
    """
    try:
        if rec.action == "throttle":
            props = await mgr.get_properties(rec.target)
            if any(getattr(props, k) != rec.params.get(k) for k in rec.previous):
                return CHANGED_SINCE
            prev = rec.previous
            await mgr.set_properties(rec.target, prev.get("memory_high"), prev.get("cpu_weight"))
        elif rec.action == "freeze":
            await mgr.thaw(rec.target)
    except UnitNotFound:
        return "unit gone"
    except SystemdError as e:
        if e.name == UNIT_INACTIVE:  # systemd thaws a unit when it stops
            return "unit inactive"
        raise
    return None
