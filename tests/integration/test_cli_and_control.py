"""sentry-v2ctl against the live daemon, as root and as a user outside both groups."""

from __future__ import annotations

import urllib.request
from collections.abc import Iterator

import pytest

from conftest import sh

pytestmark = pytest.mark.integration

OUTSIDER = "sv2-itest"


@pytest.fixture
def outsider() -> Iterator[str]:
    sh("userdel", OUTSIDER, check=False)  # left over from an interrupted run
    sh("useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", OUTSIDER)
    try:
        yield OUTSIDER
    finally:
        sh("userdel", OUTSIDER, check=False)


@pytest.mark.parametrize(
    "args", [["status"], ["policies"], ["top", "--once"], ["incidents"], ["actions"]]
)
def test_read_commands_succeed(args: list[str]) -> None:
    sh("sentry-v2ctl", *args)
    sh("sentry-v2ctl", "--json", *args)


def test_outsider_is_refused_with_exit_3(outsider: str) -> None:
    r = sh("runuser", "-u", outsider, "--", "sentry-v2ctl", "status", check=False)
    assert r.returncode == 3, r.stderr
    assert "permission denied" in r.stderr


def test_metrics_endpoint() -> None:
    with urllib.request.urlopen("http://127.0.0.1:9787/metrics", timeout=5) as resp:
        body = resp.read().decode()
    assert resp.status == 200
    assert "sentry_v2_" in body
