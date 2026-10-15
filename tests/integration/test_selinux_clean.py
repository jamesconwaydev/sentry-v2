"""The daemon runs confined, its files carry their labels, and the suite raised no denials for it.

Runs after the other daemon tests (pytest collects files in name order).
The suite's start comes from SV2_SUITE_START, which scripts/itest.sh sets
in the C locale's `%x %T` form that ausearch expects.
"""

from __future__ import annotations

import os

import pytest

from conftest import sh

pytestmark = pytest.mark.integration


def _type(context: str) -> str:
    return context.split(":")[2]


def test_daemon_runs_in_its_domain() -> None:
    pid = sh("systemctl", "show", "-P", "MainPID", "sentry-v2").stdout.strip()
    with open(f"/proc/{pid}/attr/current") as f:
        assert _type(f.read().strip("\0\n")) == "sentry_v2_t"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/usr/bin/sentry-v2", "sentry_v2_exec_t"),
        ("/etc/sentry-v2/sentry-v2.toml", "sentry_v2_conf_t"),
        ("/var/lib/sentry-v2/state", "sentry_v2_var_lib_t"),
        ("/run/sentry-v2/control.sock", "sentry_v2_var_run_t"),
    ],
)
def test_file_labels(path: str, expected: str) -> None:
    assert _type(os.getxattr(path, "security.selinux").decode().strip("\0")) == expected


def test_metrics_port_label() -> None:
    out = sh("semanage", "port", "-l").stdout
    assert any(
        line.split()[0] == "sentry_v2_metrics_port_t" and "9787" in line
        for line in out.splitlines()
        if line.strip()
    )


def test_no_denials_for_the_daemon() -> None:
    start = os.environ.get("SV2_SUITE_START", "boot")
    r = sh(
        "env", "LC_ALL=C", "ausearch", "--input-logs", "-i", "-m", "AVC,USER_AVC", "-su", "sentry_v2_t",
        "-ts", *start.split(), check=False,
    )  # fmt: skip
    # ausearch exits 1 with "<no matches>" when there is nothing to show
    assert r.returncode == 1 and "no matches" in r.stderr, r.stdout
