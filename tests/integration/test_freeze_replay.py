"""A frozen unit survives the daemon being killed: the restarted daemon thaws it on replay.

Trigger: CPU pressure. Two busy loops in one unit on this 1-vCPU host keep
one of them runnable-but-waiting most of the time, so the unit's
cpu.pressure "some" sits near 50%. That is steadier than anything driven by
a failure, and freeze needs a running target anyway. CPUQuota=50% keeps the
loops from taking the CPU away from the host's real services.
"""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import daemon_ready, records_for, sh, show, wait_for

pytestmark = pytest.mark.integration

BUSY = "yes >/dev/null & yes >/dev/null & wait"


def test_freeze_is_thawed_by_replay_after_kill(transient_unit: Callable[..., str]) -> None:
    unit = transient_unit("freeze", ["/bin/sh", "-c", BUSY], "CPUQuota=50%")

    rec = wait_for(
        lambda: next(
            (r for r in records_for(unit) if r["action"] == "freeze" and r["status"] == "applied"),
            None,
        ),
        90,
        "the freeze to be applied",
    )
    assert show(unit, "FreezerState") == "frozen"

    restarts = int(show("sentry-v2", "NRestarts"))
    sh("systemctl", "kill", "--signal=SIGKILL", "sentry-v2")
    killed = time.monotonic()
    wait_for(lambda: show(unit, "FreezerState") == "running", 15, "replay to thaw the unit")
    thawed_after = time.monotonic() - killed
    assert int(show("sentry-v2", "NRestarts")) == restarts + 1
    assert thawed_after <= 10, f"thawed {thawed_after:.1f}s after the kill"

    wait_for(daemon_ready, 30, "the restarted daemon")
    replayed = next(r for r in records_for(unit) if r["id"] == rec["id"])
    assert replayed["status"] == "rolled_back"


CONFIG = "/etc/sentry-v2/sentry-v2.toml"


def test_freeze_is_thawed_when_the_killed_daemon_cannot_start_again(
    transient_unit: Callable[..., str], tmp_path: Path
) -> None:
    unit = transient_unit("freeze", ["/bin/sh", "-c", BUSY], "CPUQuota=50%")
    wait_for(
        lambda: any(
            r["action"] == "freeze" and r["status"] == "applied" for r in records_for(unit)
        ),
        90,
        "the freeze to be applied",
    )
    assert show(unit, "FreezerState") == "frozen"

    saved = tmp_path / "sentry-v2.toml"
    shutil.copy2(CONFIG, saved)
    try:
        with open(CONFIG, "a") as f:
            f.write("this is not toml [\n")
        sh("systemctl", "kill", "--signal=SIGKILL", "sentry-v2")
        # ExecStopPost thaws it at once; the restart then exits 2 and stays down
        wait_for(
            lambda: show(unit, "FreezerState") == "running", 15, "ExecStopPost to thaw the unit"
        )
        wait_for(
            lambda: show("sentry-v2", "ExecMainStatus") == "2",
            30,
            "the restart to fail on the config",
        )
        # ExecStopPost runs again after the failed start, then the unit settles
        wait_for(
            lambda: show("sentry-v2", "ActiveState") == "failed", 30, "the daemon to stay down"
        )
        assert show(unit, "FreezerState") == "running"
    finally:
        shutil.copy2(saved, CONFIG)
        sh("restorecon", CONFIG)
        sh("systemctl", "reset-failed", "sentry-v2")
        sh("systemctl", "start", "sentry-v2", timeout=120)
    wait_for(daemon_ready, 30, "the daemon to come back")
