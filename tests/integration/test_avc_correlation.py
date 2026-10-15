"""An SELinux denial inside a failing unit ends up in that unit's bundle.

selinux/sentry_test.te confines a copy of bash in sentry_test_t and gives
it no access to sentry_test_secret_t. The unit reads the secret (denied),
sleeps so the denying process is still alive when the daemon looks up its
cgroup, then exits 1. The itest-avc-notify policy writes a bundle for it.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from conftest import ctl, sh, wait_for

pytestmark = pytest.mark.integration

HERE = Path(__file__).parent
LIBEXEC = Path("/usr/local/libexec")
SHELL = LIBEXEC / "sentry-itest-sh"
SECRET = LIBEXEC / "sentry-itest-secret"


@pytest.fixture(scope="module")
def test_domain() -> Iterator[None]:
    with tempfile.TemporaryDirectory(prefix="sv2-selinux-") as tmp:
        shutil.copy(HERE / "selinux" / "sentry_test.te", tmp)
        sh("make", "-C", tmp, "-f", "/usr/share/selinux/devel/Makefile", "sentry_test.pp")
        sh("semodule", "-i", f"{tmp}/sentry_test.pp", timeout=300)
    try:
        LIBEXEC.mkdir(parents=True, exist_ok=True)
        shutil.copy("/usr/bin/bash", SHELL)
        SECRET.write_text("not for sentry_test_t\n")
        sh("chcon", "-t", "sentry_test_exec_t", str(SHELL))
        sh("chcon", "-t", "sentry_test_secret_t", str(SECRET))
        yield
    finally:
        SHELL.unlink(missing_ok=True)
        SECRET.unlink(missing_ok=True)
        sh("semodule", "-r", "sentry_test", check=False, timeout=300)


def test_audit_collector_uses_netlink() -> None:
    assert ctl("status")["collectors"]["audit"]["source"] == "netlink"


def test_denial_is_correlated_with_the_failed_unit(
    test_domain: None, transient_unit: Callable[..., str]
) -> None:
    script = f"read -r line < {SECRET}; /usr/bin/sleep 2; exit 1"
    unit = transient_unit("avc", [str(SHELL), "-c", script])

    summary = wait_for(
        lambda: next(
            (
                i
                for i in ctl("incidents", "--unit", unit)["incidents"]
                if i["kind"] == "unit_failed"
            ),
            None,
        ),
        30,
        "the unit_failed incident",
    )
    bundle = ctl("show", summary["id"])["bundle"]
    correlations = bundle["correlations"]
    assert correlations, bundle
    best = max(correlations, key=lambda c: c["confidence"])
    assert best["confidence"] >= 0.9
    assert "pid in unit cgroup" in best["reasons"]
    assert best["avc"]["scontext_type"] == "sentry_test_t"
    assert best["avc"]["unit_at_receipt"] == unit
