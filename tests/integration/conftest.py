"""Helpers for the integration suite. Needs root and a running sentry-v2 on an EL10 host.

Every unit a test starts lives in sentry-test.slice and is stopped and
reset in a finalizer, whether the test passed or not.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from collections.abc import Callable
from typing import Any

import pytest

SLICE = "sentry-test.slice"


def sh(*argv: str, check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=timeout)  # noqa: S603


def ctl(*args: str) -> Any:
    """`sentry-v2ctl --json ...` against the live daemon, parsed."""
    return json.loads(sh("sentry-v2ctl", "--json", *args).stdout)


def show(unit: str, prop: str) -> str:
    return sh("systemctl", "show", "-P", prop, unit).stdout.strip()


def wait_for[T](fn: Callable[[], T], timeout: float, what: str, interval: float = 0.25) -> T:
    """Poll `fn` until it returns something truthy; fail with `what` on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            if value := fn():
                return value
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass  # the daemon may be restarting
        if time.monotonic() > deadline:
            pytest.fail(f"timed out after {timeout:g}s waiting for {what}")
        time.sleep(interval)


def stop_unit(name: str) -> None:
    sh("systemctl", "thaw", name, check=False)
    sh("systemctl", "stop", name, check=False)
    sh("systemctl", "reset-failed", name, check=False)


def daemon_ready() -> bool:
    return sh("systemctl", "is-active", "sentry-v2", check=False).stdout.strip() == "active" and (
        sh("sentry-v2ctl", "status", check=False).returncode == 0
    )


def records_for(unit: str) -> list[dict[str, Any]]:
    acts = ctl("actions")
    return [r for r in acts["active"] + acts["recent"] if r["target"] == unit]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "last: run after every other collected test")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Move tests marked `last` to the end, whatever file they live in."""
    items.sort(key=lambda item: item.get_closest_marker("last") is not None)


@pytest.fixture
def transient_unit(request: pytest.FixtureRequest) -> Callable[..., str]:
    """Start `cmd` as a transient service in sentry-test.slice; returns the unit name."""

    def start(prefix: str, cmd: list[str], *props: str) -> str:
        name = f"sentry-itest-{prefix}-{uuid.uuid4().hex[:8]}.service"
        request.addfinalizer(lambda: stop_unit(name))
        flags = [a for p in ("MemoryMax=96M", *props) for a in ("-p", p)]
        sh("systemd-run", "--unit", name, "--slice", SLICE, *flags, "--", *cmd)
        return name

    return start


@pytest.fixture(autouse=True)
def _daemon_running() -> None:
    wait_for(daemon_ready, 30, "sentry-v2 to be active")
