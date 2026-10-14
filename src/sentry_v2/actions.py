"""How each action kind is captured, applied and undone against systemd.

The executor decides when; this module only knows what. Capture (`prepare`)
is separate from `apply` so the previous values can be journalled in
between.
"""

from __future__ import annotations

import hashlib
import shutil
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
            if props.freezer_state != "running":
                raise Refused(f"already {props.freezer_state}")
            return {"freezer_state": props.freezer_state}, {"cgroup": props.cgroup}
        case BackupReload():
            files = [props.fragment_path, *props.drop_in_paths, *map(str, spec.paths)]
            return {}, {"files": [f for f in files if f]}
        case Notify():  # pragma: no cover - the executor never prepares a notify
            return {}, {}


def backup(unit: str, files: list[str], backups_dir: Path, now: float) -> str:
    """Copy `files` under `backups_dir/<unit>/<ts>/files/<abs path>` with a sha256 manifest.

    Returns the backup id `<unit>/<ts>`. Copies keep mode and mtime.
    """
    backup_id = f"{unit}/{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}"
    bdir = backups_dir / backup_id
    bdir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    bdir.mkdir(mode=0o700)
    manifest = []
    for src in files:
        rel = Path("files") / Path(src).relative_to("/")
        dest = bdir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
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


async def rollback(rec: ActionRecord, mgr: SystemdManager) -> str | None:
    """Undo `rec`. Returns a note when there was nothing left to undo; raises on failure."""
    try:
        if rec.action == "throttle":
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
