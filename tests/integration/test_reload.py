"""A broken policy file is reported by reload and leaves the running policies in place."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import ctl, sh

pytestmark = pytest.mark.integration

BROKEN = Path("/etc/sentry-v2/policies.d/99-itest-broken.toml")


@pytest.fixture
def broken_policy() -> Iterator[Path]:
    BROKEN.write_text(
        '[[policy]]\nname = "itest-broken"\n\n[policy.when]\nsignal = "psi"\n'
        'resource = "memory"\nthreshold = "100ms/2s"\nbogus = 1\n'
        'cgroups = ["sentry.slice/sentry-test.slice/sentry-itest-none-*.service"]\n\n'
        '[[policy.do]]\naction = "notify"\n'
    )
    try:
        yield BROKEN
    finally:
        BROKEN.unlink(missing_ok=True)
        sh("systemctl", "reload", "sentry-v2", check=False)


def _names() -> set[str]:
    return {p["name"] for p in ctl("policies")["policies"]}


def test_broken_policy_keeps_old_config_then_clears(broken_policy: Path) -> None:
    before = _names()
    sh("systemctl", "reload", "sentry-v2")
    error = ctl("status")["last_reload_error"]
    assert error is not None
    assert broken_policy.name in error
    assert "bogus" in error
    assert _names() == before
    assert ctl("policies")["last_reload_error"] == error

    broken_policy.unlink()
    sh("systemctl", "reload", "sentry-v2")
    assert ctl("status")["last_reload_error"] is None
    assert _names() == before
