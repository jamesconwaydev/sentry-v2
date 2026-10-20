"""An SELinux denial inside a failing unit ends up in that unit's bundle.

selinux/sentry_test.te confines a copy of bash in sentry_test_t and gives
it no access to sentry_test_secret_t. The unit reads the secret (denied),
sleeps so the denying process is still alive when the daemon looks up its
cgroup, then exits 1. The itest-avc-notify policy writes a bundle for it.

A second unit in sentry_test_other_t is denied the same file in the same
window. It shares the slice but not the cgroup, the domain or the binary
name, so it scores nothing and must stay out of the first unit's bundle.
"""

from __future__ import annotations

import re
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
OTHER = LIBEXEC / "sentry-itest-other"
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
        shutil.copy("/usr/bin/bash", OTHER)
        SECRET.write_text("not for sentry_test_t\n")
        sh("chcon", "-t", "sentry_test_exec_t", str(SHELL))
        sh("chcon", "-t", "sentry_test_other_exec_t", str(OTHER))
        sh("chcon", "-t", "sentry_test_secret_t", str(SECRET))
        yield
    finally:
        SHELL.unlink(missing_ok=True)
        OTHER.unlink(missing_ok=True)
        SECRET.unlink(missing_ok=True)
        sh("semodule", "-r", "sentry_test", check=False, timeout=300)


def test_audit_collector_uses_netlink() -> None:
    audit = ctl("status")["collectors"]["audit"]
    assert audit["source"] == "netlink"
    # the default is net.core.rmem_default; a setsockopt that went through
    # (not denied by the policy module) gets twice min(asked, rmem_max)
    rmem_default = int(Path("/proc/sys/net/core/rmem_default").read_text())
    assert audit["rcvbuf"] > rmem_default and audit["overruns"] == 0


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


def _denial_times(scontext_type: str) -> list[int]:
    """Microsecond timestamps of today's AVC denials from `scontext_type`."""
    out = sh("ausearch", "--input-logs", "-m", "AVC", "-ts", "today", check=False).stdout
    return [
        int(m[1]) * 1_000_000 + int(m[2]) * 1000
        for line in out.splitlines()
        if "denied" in line and f":{scontext_type}:" in line
        if (m := re.search(r"audit\((\d+)\.(\d+):", line))
    ]


def test_unrelated_denial_in_window_is_left_out(
    test_domain: None, transient_unit: Callable[..., str]
) -> None:
    other = transient_unit(
        "other", [str(OTHER), "-c", f"read -r line < {SECRET}; /usr/bin/sleep 10"]
    )
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
    types = {c["avc"]["scontext_type"]: c for c in bundle["correlations"]}
    assert types["sentry_test_t"]["confidence"] >= 0.9, bundle
    assert "sentry_test_other_t" not in types, bundle

    # The other denial really landed inside the correlation window
    # (5 s before the failure to 1 s after), so leaving it out was a decision.
    failed = bundle["incident"]["ts_us"]
    assert any(
        failed - 5_000_000 <= t <= failed + 1_000_000 for t in _denial_times("sentry_test_other_t")
    ), other
