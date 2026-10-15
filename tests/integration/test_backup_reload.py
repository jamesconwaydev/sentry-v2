"""backup_reload copies a unit's files before reloading it, and restore puts them back.

Trigger: the unit's own failure. It exits 3 on its first start and runs
normally after Restart=on-failure brings it back 200ms later, so by the
time the failure incident is out (correlation.after = 1s) the unit is
active again and ReloadUnit has something to reload.

The unit file lives in /etc/systemd/system, or in /usr/lib/systemd/system
like a package's, which the daemon's sandbox keeps read-only. Either way
only the drop-in is changed, so restore skips the fragment.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import SLICE, ctl, records_for, sh, stop_unit, wait_for

pytestmark = pytest.mark.integration

UNITS = Path("/etc/systemd/system")
VENDOR_UNITS = Path("/usr/lib/systemd/system")
BACKUPS = Path("/var/lib/sentry-v2/backups")
DROP_IN = "[Service]\nEnvironment=SENTRY_ITEST=original\n"


@pytest.fixture(params=[UNITS, VENDOR_UNITS], ids=["etc", "usr-lib"])
def flaky_unit(request: pytest.FixtureRequest) -> Iterator[tuple[str, Path]]:
    name = f"sentry-itest-backup-{uuid.uuid4().hex[:8]}.service"
    flag = Path(f"/run/{name}.flag")
    fragment, drop_in_dir = request.param / name, UNITS / f"{name}.d"
    fragment.write_text(
        "[Unit]\nDescription=sentry-v2 integration test (backup_reload)\n\n"
        f"[Service]\nSlice={SLICE}\nMemoryMax=96M\n"
        f"ExecStart=/bin/sh -c 'if [ ! -e {flag} ]; then touch {flag}; exit 3; fi; exec sleep 300'\n"
        "ExecReload=/bin/true\nRestart=on-failure\nRestartSec=200ms\n"
    )
    drop_in_dir.mkdir()
    (drop_in_dir / "10-itest.conf").write_text(DROP_IN)
    try:
        sh("systemctl", "daemon-reload")
        sh("systemctl", "start", "--no-block", name)
        yield name, fragment
    finally:
        stop_unit(name)
        # an interrupted restore can leave .<name>.sentry-v2-restore files behind
        shutil.rmtree(drop_in_dir, ignore_errors=True)
        for p in (fragment, UNITS / f".{name}.sentry-v2-restore", flag):
            p.unlink(missing_ok=True)
        sh("systemctl", "daemon-reload")


def _label(path: Path) -> str:
    return os.getxattr(path, "security.selinux").decode().strip("\0").split(":")[2]


def test_backup_reload_and_restore(flaky_unit: tuple[str, Path]) -> None:
    name, fragment = flaky_unit
    rec = wait_for(
        lambda: next((r for r in records_for(name) if r["status"] in ("applied", "failed")), None),
        30,
        "the backup_reload record",
    )
    assert rec["status"] == "applied", rec
    backup_id = rec["backup_id"]
    bdir = BACKUPS / backup_id

    manifest = (bdir / "MANIFEST.sha256").read_text().splitlines()
    copied = {}
    for line in manifest:
        digest, rel = line.split("  ", 1)
        assert hashlib.sha256((bdir / rel).read_bytes()).hexdigest() == digest
        copied["/" + rel.removeprefix("files/")] = digest
    drop_in = UNITS / f"{name}.d" / "10-itest.conf"
    assert set(copied) == {str(fragment), str(drop_in)}

    # copies take the backup directory's label, not the unit file's
    assert _label(bdir / "files" / str(drop_in).lstrip("/")) == "sentry_v2_var_lib_t"

    drop_in.write_text("[Service]\nEnvironment=SENTRY_ITEST=changed\n")
    restored = ctl("restore", backup_id)
    assert restored["restored"] == [str(drop_in)]
    assert restored["skipped"] == [str(fragment)]
    assert drop_in.read_text() == DROP_IN
    assert _label(drop_in) == "systemd_unit_file_t"
