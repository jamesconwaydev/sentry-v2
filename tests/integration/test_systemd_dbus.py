"""SystemdContract against the real system bus. Needs root on an EL10 host."""

from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_systemd import SystemdContract

from sentry_v2.systemd import DBusSystemd

pytestmark = pytest.mark.integration


def _sh(*argv: str, check: bool = False) -> None:
    subprocess.run(argv, check=check, capture_output=True)  # noqa: S603


class TestDBusSystemd(SystemdContract):
    @pytest.fixture
    def unit(self, request: pytest.FixtureRequest) -> Iterator[str]:
        name = f"sentry-test-dbus-{uuid.uuid4().hex[:8]}.service"
        request.addfinalizer(
            lambda: (_sh("systemctl", "stop", name), _sh("systemctl", "reset-failed", name))
        )
        _sh(
            "systemd-run", "--unit", name, "--slice", "sentry-test.slice",
            "-p", "MemoryMax=64M", "-p", "ExecReload=/bin/true", "sleep", "300",
            check=True,
        )  # fmt: skip
        time.sleep(0.5)
        yield name

    @pytest.fixture
    def manager(self) -> Iterator[DBusSystemd]:
        ex = ThreadPoolExecutor(max_workers=1)
        yield DBusSystemd(ex)
        ex.shutdown()
