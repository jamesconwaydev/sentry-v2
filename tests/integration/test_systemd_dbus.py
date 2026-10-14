"""SystemdContract against the real system bus. Needs root on an EL10 host."""

from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

from contracts import SystemdContract
from sentry_v2.systemd import DBusSystemd

pytestmark = pytest.mark.integration


def _sh(*argv: str, check: bool = False) -> None:
    subprocess.run(argv, check=check, capture_output=True)  # noqa: S603


class TestDBusSystemd(SystemdContract):
    @staticmethod
    def _start(request: pytest.FixtureRequest, *props: str, cmd: str = "sleep 300") -> str:
        name = f"sentry-test-dbus-{uuid.uuid4().hex[:8]}.service"
        request.addfinalizer(
            lambda: (
                _sh("systemctl", "thaw", name),
                _sh("systemctl", "stop", name),
                _sh("systemctl", "reset-failed", name),
            )
        )
        flags = [a for p in props for a in ("-p", p)]
        _sh(
            "systemd-run",
            "--unit",
            name,
            "--slice",
            "sentry-test.slice",
            *flags,
            *cmd.split(),
            check=True,
        )
        return name

    @pytest.fixture
    def unit(self, request: pytest.FixtureRequest) -> str:
        return self._start(request, "MemoryMax=64M", "ExecReload=/bin/true")

    @pytest.fixture
    def inactive_unit(self, request: pytest.FixtureRequest) -> str:
        # a failed unit stays loaded, so GetUnit still finds it
        name = self._start(request, cmd="/bin/false")
        time.sleep(0.5)
        return name

    @pytest.fixture
    def manager(self) -> Iterator[DBusSystemd]:
        m = DBusSystemd()
        yield m
        m.close()
