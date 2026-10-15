from pathlib import Path

import pytest

from sentry_v2.events import AvcEvent, Incident, PsiEvent, UnitEvent
from sentry_v2.policy import (
    AvcWhen,
    Notify,
    Policy,
    PolicyEngine,
    PsiWhen,
    UnitFailedWhen,
    effective_mode,
    is_protected,
    target_matches,
)


def test_is_protected() -> None:
    assert is_protected("systemd-resolved.service", [])
    assert is_protected("sshd.service", [])
    assert is_protected("nginx.service", ["nginx.service"])
    assert is_protected("web-1.service", ["web-*.service"])
    assert not is_protected("batch-1.service", [])


@pytest.mark.parametrize("unit", ["user-1000.slice", "session-3.scope", "user@1000.service"])
def test_user_sessions_are_protected(unit: str) -> None:
    assert is_protected(unit, [])


class Clock:
    now = 1000.0

    def __call__(self) -> float:
        return self.now


def unit_incident(target: str, result: str = "watchdog") -> Incident:
    ev = UnitEvent(ts_us=1, unit=target, kind="failed", result=result)
    return Incident("i", "unit_failed", 1, target, ev, (), ())


def policy(name: str, when: object, cooldown: float = 60.0) -> Policy:
    return Policy(name, "enforce", cooldown, when, (Notify(),), Path("p.toml"))  # type: ignore[arg-type]


def test_cooldown_per_target() -> None:
    clock = Clock()
    engine = PolicyEngine([policy("p", UnitFailedWhen(("batch-*.service",)))], clock)
    assert len(engine.plan(unit_incident("batch-1.service"))) == 1
    clock.now += 30
    assert engine.plan(unit_incident("batch-1.service")) == []
    assert len(engine.plan(unit_incident("batch-2.service"))) == 1
    clock.now += 31
    assert len(engine.plan(unit_incident("batch-1.service"))) == 1


def test_result_filter_and_replace() -> None:
    engine = PolicyEngine([], Clock())
    assert engine.plan(unit_incident("a.service")) == []
    engine.replace([policy("p", UnitFailedWhen(("*.service",), ("timeout",)))])
    assert engine.plan(unit_incident("a.service", "watchdog")) == []
    assert len(engine.plan(unit_incident("a.service", "timeout"))) == 1


def psi_incident(
    resource: str = "memory",
    stall_us: int = 150_000,
    window_us: int = 1_000_000,
    sustained: float = 5.0,
) -> Incident:
    ev = PsiEvent(
        ts_us=1,
        cgroup="/system.slice/x.service",
        resource=resource,  # type: ignore[arg-type]
        kind="some",
        avg10=1,
        avg60=1,
        avg300=1,
        total_us=1,
        triggered=True,
        stall_us=stall_us,
        window_us=window_us,
    )
    return Incident("i", "psi", 1, "/system.slice/x.service", ev, (), (), sustained)


def test_psi_match() -> None:
    when = PsiWhen("memory", "some", 150_000, 1_000_000, 5.0, ("system.slice/*.service",))
    engine = PolicyEngine([policy("p", when)], Clock())
    assert engine.plan(psi_incident("cpu")) == []
    assert len(engine.plan(psi_incident())) == 1
    assert engine.plan(psi_incident(stall_us=500_000)) == []
    assert engine.plan(psi_incident(window_us=2_000_000)) == []
    assert engine.plan(psi_incident(sustained=30.0)) == []
    # a unit incident never satisfies a psi policy
    assert engine.plan(unit_incident("x.service")) == []


def avc(serial: int, typ: str) -> AvcEvent:
    return AvcEvent(
        ts_us=serial,
        serial=serial,
        denied=True,
        perms=("read",),
        scontext=f"u:r:{typ}:s0",
        scontext_type=typ,
        tcontext="u:o:etc_t:s0",
        tclass="file",
    )


def test_avc_match_counts_types() -> None:
    evs = (avc(1, "httpd_t"), avc(2, "httpd_t"), avc(3, "sshd_t"))
    inc = Incident("i", "avc", 3, "httpd_t", evs[0], evs, ())
    assert len(PolicyEngine([policy("a", AvcWhen(("httpd_t",), 2))], Clock()).plan(inc)) == 1
    assert PolicyEngine([policy("b", AvcWhen(("httpd_t",), 3))], Clock()).plan(inc) == []
    assert len(PolicyEngine([policy("c", AvcWhen((), 3))], Clock()).plan(inc)) == 1


@pytest.mark.parametrize(
    ("daemon", "pol", "expected"),
    [
        ("dry-run", "dry-run", "dry-run"),
        ("dry-run", "enforce", "dry-run"),
        ("enforce", "dry-run", "dry-run"),
        ("enforce", "enforce", "enforce"),
    ],
)
def test_effective_mode(daemon: str, pol: str, expected: str) -> None:
    assert effective_mode(daemon, pol) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("nginx.service", "system.slice/nginx.service", True),
        ("nginx.service", "/system.slice/nginx.service", True),
        ("nginx.service", "nginx.service", True),
        ("nginx.service", "system.slice/nginx.service/extra", False),
        ("batch-*.service", "system.slice/batch-1.service", True),
        ("system.slice/batch-*.service", "system.slice/batch-1.service", True),
        ("system.slice/batch-*.service", "user.slice/batch-1.service", False),
        ("system.slice/nginx.service", "nginx.service", False),
    ],
)
def test_target_matches(pattern: str, path: str, expected: bool) -> None:
    assert target_matches(pattern, path) is expected


def test_engine_bare_name_and_path_patterns() -> None:
    def when(pattern: str) -> PsiWhen:
        return PsiWhen("memory", "some", 150_000, 1_000_000, 5.0, (pattern,))

    for pattern, n in [
        ("x.service", 1),
        ("system.slice/x.service", 1),
        ("user.slice/x.service", 0),
    ]:
        engine = PolicyEngine([policy("p", when(pattern))], Clock())
        assert len(engine.plan(psi_incident())) == n


def test_cooldown_history_pruned() -> None:
    clock = Clock()
    engine = PolicyEngine([policy("p", UnitFailedWhen(("*.service",)), 10.0)], clock)
    engine.plan(unit_incident("a.service"))
    clock.now += 11
    engine.plan(unit_incident("b.service"))
    assert list(engine._last) == [("p", "b.service")]
