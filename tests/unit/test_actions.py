import asyncio
import dataclasses
import hashlib
import os
from pathlib import Path

import pytest

from contracts import NGINX
from sentry_v2 import actions
from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.policy import BackupReload, Freeze, Throttle
from sentry_v2.state import ActionRecord
from sentry_v2.systemd import UNSET, FakeSystemd, SystemdError, UnitNotFound
from sentry_v2.units import Percent

run = asyncio.run
MiB = 1024**2
UNIT = "nginx.service"


def fake(**props: object) -> FakeSystemd:
    return FakeSystemd(units={UNIT: dataclasses.replace(NGINX, **props)})  # type: ignore[arg-type]


def fs_with_memory(tmp_path: Path, current: int) -> CgroupFS:
    d = tmp_path / "cgroup" / NGINX.cgroup
    d.mkdir(parents=True)
    (d / "memory.current").write_text(f"{current}\n")
    return CgroupFS(tmp_path / "cgroup")


def rec(action: str, previous: dict[str, object]) -> ActionRecord:
    return ActionRecord(
        id="r", policy="p", action=action, target=UNIT, mode="enforce", status="applied",
        previous=previous, applied_at=0.0, expires_at=60.0, error=None, incident_id="i",
    )  # type: ignore[arg-type]  # fmt: skip


def test_throttle_percent_of_memory_current(tmp_path: Path) -> None:
    fs = fs_with_memory(tmp_path, 1000 * MiB)
    prev, params = run(actions.prepare(Throttle(Percent(50), 20, 60), UNIT, fake(), fs))
    assert prev == {"memory_high": UNSET, "cpu_weight": UNSET}
    assert params == {"memory_high": 500 * MiB, "cpu_weight": 20}


def test_throttle_percent_floored_at_32_mib(tmp_path: Path) -> None:
    fs = fs_with_memory(tmp_path, 10 * MiB)
    prev, params = run(actions.prepare(Throttle(Percent(50), None, 60), UNIT, fake(), fs))
    assert prev == {"memory_high": UNSET}
    assert params == {"memory_high": 32 * MiB, "cpu_weight": None}


def test_throttle_apply_and_rollback_restore_raw_values(tmp_path: Path) -> None:
    mgr = fake(cpu_weight=100)
    spec = Throttle(64 * MiB, 10, 60)
    prev, params = run(actions.prepare(spec, UNIT, mgr, CgroupFS(tmp_path)))
    run(actions.apply(spec, UNIT, params, mgr))
    assert (mgr.units[UNIT].memory_high, mgr.units[UNIT].cpu_weight) == (64 * MiB, 10)
    assert run(actions.rollback(rec("throttle", prev), mgr)) is None
    assert (mgr.units[UNIT].memory_high, mgr.units[UNIT].cpu_weight) == (UNSET, 100)


def test_freeze_refuses_already_frozen(tmp_path: Path) -> None:
    with pytest.raises(actions.Refused, match="already frozen"):
        run(actions.prepare(Freeze(60), UNIT, fake(freezer_state="frozen"), CgroupFS(tmp_path)))


def test_freeze_apply_and_thaw(tmp_path: Path) -> None:
    mgr = fake()
    prev, params = run(actions.prepare(Freeze(60), UNIT, mgr, CgroupFS(tmp_path)))
    assert prev == {"freezer_state": "running"}
    assert params == {"cgroup": NGINX.cgroup}
    run(actions.apply(Freeze(60), UNIT, params, mgr))
    assert mgr.units[UNIT].freezer_state == "frozen"
    run(actions.rollback(rec("freeze", prev), mgr))
    assert mgr.units[UNIT].freezer_state == "running"


def test_rollback_unit_gone_and_inactive() -> None:
    assert run(actions.rollback(rec("freeze", {}), FakeSystemd())) == "unit gone"
    mgr = fake()
    mgr.fail["thaw"] = SystemdError("org.freedesktop.systemd1.UnitInactive", "x")
    assert run(actions.rollback(rec("freeze", {}), mgr)) == "unit inactive"
    mgr.fail["thaw"] = SystemdError("org.freedesktop.DBus.Error.NoReply", "x")
    with pytest.raises(SystemdError):
        run(actions.rollback(rec("freeze", {}), mgr))


def test_freeze_refuses_inactive_unit(tmp_path: Path) -> None:
    with pytest.raises(actions.Refused, match="unit inactive"):
        run(actions.prepare(Freeze(60), UNIT, fake(active_state="failed"), CgroupFS(tmp_path)))


def test_describe_dry_run_params() -> None:
    assert actions.describe(Throttle(Percent(90), 20, 60)) == {
        "memory_high": "90%",
        "cpu_weight": 20,
    }
    assert actions.describe(Throttle(64 * MiB, None, 60)) == {
        "memory_high": 64 * MiB,
        "cpu_weight": None,
    }
    assert actions.describe(Freeze(60)) == {}


def test_backup_refuses_path_escaping_backup_dir(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes"):
        actions.backup(UNIT, ["/../../etc/passwd"], tmp_path / "b", now=0.0)


def test_backup_dirs_are_private(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    actions.backup(UNIT, [str(src)], tmp_path / "b", now=0.0)
    for d in (tmp_path / "b", tmp_path / "b" / UNIT, tmp_path / "b" / UNIT / "19700101T000000Z"):
        assert d.stat().st_mode & 0o777 == 0o700


def test_prepare_unknown_unit(tmp_path: Path) -> None:
    with pytest.raises(UnitNotFound):
        run(actions.prepare(Freeze(60), UNIT, FakeSystemd(), CgroupFS(tmp_path)))


def test_backup_reload_manifest_matches_copies(tmp_path: Path) -> None:
    etc = tmp_path / "etc"
    (etc / "nginx.service.d").mkdir(parents=True)
    frag = etc / "nginx.service"
    frag.write_text("[Service]\nExecStart=/usr/sbin/nginx\n")
    dropin = etc / "nginx.service.d" / "override.conf"
    dropin.write_text("[Service]\nMemoryMax=1G\n")
    extra = etc / "nginx.conf"
    extra.write_text("worker_processes 1;\n")
    os.utime(extra, (1000, 1000))
    mgr = fake(fragment_path=str(frag), drop_in_paths=(str(dropin),))
    spec = BackupReload(paths=(extra,))

    prev, params = run(actions.prepare(spec, UNIT, mgr, CgroupFS(tmp_path)))
    assert prev == {}
    backups = tmp_path / "backups"
    bid = actions.backup(UNIT, params["files"], backups, now=0.0)
    assert bid == "nginx.service/19700101T000000Z"
    bdir = backups / bid
    lines = (bdir / "MANIFEST.sha256").read_text().splitlines()
    assert len(lines) == 3
    for line in lines:
        digest, rel = line.split("  ", 1)
        copied = bdir / rel
        original = Path("/") / Path(rel).relative_to("files")
        assert digest == hashlib.sha256(copied.read_bytes()).hexdigest()
        assert copied.read_bytes() == original.read_bytes()
    assert (bdir / "files" / str(extra).lstrip("/")).stat().st_mtime == 1000

    run(actions.apply(spec, UNIT, params, mgr))
    assert [c[0] for c in mgr.calls].count("reload") == 1


def test_backup_missing_file_fails(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        actions.backup(UNIT, [str(tmp_path / "nope")], tmp_path / "b", now=0.0)
