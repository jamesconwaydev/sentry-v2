from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sentry_v2.config_types import CorrelationConfig
from sentry_v2.correlate import AUDIT_WAIT_MAX_US, Correlator, score
from sentry_v2.events import AvcEvent, PsiEvent, UnitEvent
from sentry_v2.policy import Notify, Policy, PolicyEngine, PsiWhen

T = 1_700_000_000_000_000  # µs
S = 1_000_000


class Clock:
    def __init__(self, now_us: int = T) -> None:
        self.now_us = now_us

    def __call__(self) -> float:
        return self.now_us / S


def avc(ts: int, **kw: Any) -> AvcEvent:
    fields: dict[str, Any] = {
        "serial": 1,
        "denied": True,
        "perms": ("read",),
        "scontext": "system_u:system_r:httpd_t:s0",
        "scontext_type": "httpd_t",
        "tcontext": "system_u:object_r:shadow_t:s0",
        "tclass": "file",
        "pid": 42,
        "comm": "httpd",
        "exe": "/usr/sbin/httpd",
        "cgroup_at_receipt": "system.slice/web.service",
        "unit_at_receipt": "web.service",
    }
    fields.update(kw)
    return AvcEvent(ts_us=ts, **fields)


def failed(ts: int, unit: str = "web.service", **kw: Any) -> UnitEvent:
    return UnitEvent(ts_us=ts, unit=unit, kind="failed", result="exit-code", **kw)


def correlator(clock: Clock | None = None, **kw: Any) -> Correlator:
    return Correlator(CorrelationConfig(), [], clock or Clock(), **kw)


def run_failure(avcs: list[AvcEvent], fail_ts: int = T, tick_at: int | None = None) -> Any:
    clock = Clock(fail_ts)
    c = correlator(clock)
    for a in sorted([*avcs, failed(fail_ts)], key=lambda e: e.ts_us):
        assert c.ingest(a) == []
    incidents = c.tick(tick_at if tick_at is not None else fail_ts + S)
    assert len(incidents) == 1
    return incidents[0]


def test_avc_in_unit_cgroup_before_failure_correlates() -> None:
    inc = run_failure([avc(T - 4_900_000)])
    assert inc.kind == "unit_failed"
    assert inc.target == "web.service"
    assert len(inc.correlations) == 1
    corr = inc.correlations[0]
    assert corr.reasons == ("pid in unit cgroup",)
    assert corr.confidence == pytest.approx(0.9)


def test_second_avc_scores_against_domain_taught_by_first() -> None:
    inc = run_failure([avc(T - 3 * S), avc(T - 2 * S)])
    assert [c.confidence for c in inc.correlations] == pytest.approx([0.9, 1 - 0.1 * 0.4])
    assert inc.correlations[1].reasons == (
        "pid in unit cgroup",
        "scontext type matches unit domain",
    )


def test_domain_remembered_beyond_retention() -> None:
    clock = Clock()
    c = correlator(clock)
    c.ingest(avc(T))
    clock.now_us = T + 120 * S
    user_avc = avc(
        T + 119 * S, pid=None, comm=None, exe=None, cgroup_at_receipt=None, unit_at_receipt=None
    )
    c.ingest(user_avc)
    c.ingest(failed(T + 120 * S))
    [inc] = c.tick(T + 121 * S)
    assert inc.correlations[0].confidence == pytest.approx(0.6)


def test_cgroup_match_alone_scores_point_nine() -> None:
    c = score(avc(T, scontext_type="unconfined_service_t"), "web.service", None, set())
    assert c is not None
    assert c.confidence == pytest.approx(0.9)
    assert c.reasons == ("pid in unit cgroup",)


@pytest.mark.parametrize(
    ("offset", "included"),
    [
        (-5_100_000, False),
        (-5_000_000, True),
        (900_000, True),
        (1_000_000, True),
        (1_100_000, False),
    ],
)
def test_window_bounds(offset: int, included: bool) -> None:
    inc = run_failure([avc(T + offset)], tick_at=T + 2 * S)
    assert bool(inc.correlations) is included


def test_not_finalised_before_after_window() -> None:
    c = correlator()
    c.ingest(failed(T))
    assert c.tick(T + 999_999) == []
    assert len(c.tick(T + S)) == 1
    assert c.tick(T + 2 * S) == []


def test_ms_audit_timestamp_vs_us_journal() -> None:
    base = 1_000_000_000_000_000_000
    inc = run_failure([avc(base + 123_000)], fail_ts=base + 123_456)
    assert len(inc.correlations) == 1


def test_ms_truncation_tolerated_at_lower_bound() -> None:
    # audit ts truncates to ms, so a denial right at t - 5 s may read up to 999 µs early
    inc = run_failure([avc(T - 5_000_999)])
    assert len(inc.correlations) == 1


def test_avc_from_other_unit_excluded() -> None:
    other = avc(
        T - S,
        scontext_type="sshd_t",
        cgroup_at_receipt="system.slice/other.service",
        unit_at_receipt="other.service",
        comm="sshd",
        exe="/usr/sbin/sshd",
    )
    inc = run_failure([other])
    assert inc.correlations == ()
    assert score(other, "web.service", "httpd_t", {"httpd"}) is None


def test_sibling_instance_with_same_domain_and_binary_excluded() -> None:
    own = avc(
        T - 2 * S, cgroup_at_receipt="system.slice/web@a.service", unit_at_receipt="web@a.service"
    )
    sibling = avc(
        T - S,
        pid=43,
        cgroup_at_receipt="system.slice/web@b.service",
        unit_at_receipt="web@b.service",
    )
    clock = Clock(T)
    c = correlator(clock)
    for e in (own, sibling, failed(T, unit="web@a.service")):
        assert c.ingest(e) == []
    (inc,) = c.tick(T + S)
    # the sibling shares httpd_t and the httpd binary, but its process sat in
    # another unit's cgroup: that's evidence against, not a 0.76 link
    assert [x.avc.unit_at_receipt for x in inc.correlations] == ["web@a.service"]
    assert score(sibling, "web@a.service", "httpd_t", {"httpd"}) is None


def test_unknown_cgroup_still_scores_on_domain_and_binary() -> None:
    gone = avc(T - S, cgroup_at_receipt=None, unit_at_receipt=None)
    c = score(gone, "web.service", "httpd_t", {"httpd"})
    assert c is not None
    assert c.confidence == pytest.approx(0.76)


def test_pid_exited_before_failure_still_matches_by_receipt_cgroup() -> None:
    gone = avc(T - S, unit_at_receipt=None, cgroup_at_receipt="system.slice/web.service")
    c = score(gone, "web.service", None, set())
    assert c is not None
    assert c.confidence == pytest.approx(0.9)


def test_domain_learned_from_earlier_avc() -> None:
    learned = avc(T - 30 * S, scontext_type="httpd_t")
    user_avc = avc(
        T - S, pid=None, comm=None, exe=None, cgroup_at_receipt=None, unit_at_receipt=None
    )
    inc = run_failure([learned, user_avc])
    by_ts = {c.avc.ts_us: c for c in inc.correlations}
    assert by_ts[T - S].reasons == ("scontext type matches unit domain",)
    assert by_ts[T - S].confidence == pytest.approx(0.6)
    assert T - 30 * S not in by_ts  # outside the window


def test_comm_match_alone_is_below_threshold() -> None:
    a = avc(T, scontext_type="x_t", cgroup_at_receipt=None, unit_at_receipt=None)
    c = score(a, "web.service", None, {"httpd"})
    assert c is not None
    assert c.confidence == pytest.approx(0.4)
    assert c.reasons == ("comm matches ExecStart",)


def test_comm_parentheses_stripped_and_systemd_executor_ignored() -> None:
    a = avc(
        T,
        scontext_type="x_t",
        cgroup_at_receipt=None,
        unit_at_receipt=None,
        comm="(cat)",
        exe="/usr/lib/systemd/systemd-executor",
    )
    assert score(a, "x.service", None, {"cat"}) is not None
    assert score(a, "x.service", None, {"systemd-executor"}) is None
    b = avc(T, cgroup_at_receipt=None, unit_at_receipt=None, comm=None, exe="/usr/bin/cat")
    assert score(b, "x.service", None, {"cat"}) is not None


def test_unit_info_supplies_domain_and_exec_names() -> None:
    def info(unit: str) -> tuple[set[str], str | None, int | None]:
        assert unit == "web.service"
        return {"httpd"}, "httpd_t", None

    c = correlator(unit_info=info)
    a = avc(T - S, cgroup_at_receipt=None, unit_at_receipt=None)
    c.ingest(a)
    c.ingest(failed(T))
    [inc] = c.tick(T + S)
    assert inc.correlations[0].reasons == (
        "scontext type matches unit domain",
        "comm matches ExecStart",
    )
    assert inc.correlations[0].confidence == pytest.approx(1 - 0.4 * 0.6)


def test_granted_avcs_ignored() -> None:
    inc = run_failure([avc(T - S, denied=False)])
    assert inc.correlations == ()


def test_related_exit_event_and_duplicate_failure_merged() -> None:
    c = correlator()
    exited = UnitEvent(
        ts_us=T - 10, unit="web.service", kind="exited", exit_status="1", invocation_id="abc"
    )
    c.ingest(exited)
    c.ingest(failed(T, invocation_id="abc"))
    dup = UnitEvent(
        ts_us=T + 5, unit="web.service", kind="start_failed", result="failed", invocation_id="abc"
    )
    c.ingest(dup)
    c.ingest(UnitEvent(ts_us=T, unit="web.service", kind="exited", invocation_id="other"))
    [inc] = c.tick(T + S)
    assert inc.related == (exited, dup)
    assert inc.id != ""


def test_duplicate_failure_after_finalisation_ignored() -> None:
    c = correlator()
    c.ingest(failed(T, invocation_id="abc"))
    assert len(c.tick(T + S)) == 1
    c.ingest(
        UnitEvent(ts_us=T + 2 * S, unit="web.service", kind="start_failed", invocation_id="abc")
    )
    c.ingest(failed(T + 3 * S))  # no invocation id: never deduplicated
    assert len(c.tick(T + 5 * S)) == 1


def test_unit_failed_replaces_pending_start_failed() -> None:
    c = correlator()
    job = UnitEvent(
        ts_us=T, unit="web.service", kind="start_failed", result="failed", invocation_id="abc"
    )
    unit = failed(T + 10, invocation_id="abc")
    c.ingest(job)
    c.ingest(unit)
    [inc] = c.tick(T + 2 * S)
    assert inc.trigger == unit
    assert inc.related == (job,)


def test_start_failed_creates_incident() -> None:
    c = correlator()
    c.ingest(UnitEvent(ts_us=T, unit="a.service", kind="start_failed", result="failed"))
    [inc] = c.tick(T + S)
    assert inc.kind == "unit_failed"
    assert inc.target == "a.service"


def test_out_of_order_events_are_found() -> None:
    c = correlator()
    c.ingest(failed(T))
    c.ingest(avc(T + 500_000))
    c.ingest(avc(T - 2 * S))  # late arrival
    [inc] = c.tick(T + S)
    assert [x.avc.ts_us for x in inc.correlations] == [T - 2 * S, T + 500_000]


def test_retention_evicts_old_events() -> None:
    clock = Clock()
    c = correlator(clock)
    c.ingest(avc(T, scontext_type="old_t", unit_at_receipt="web.service"))
    assert len(c) == 1
    clock.now_us = T + 60 * S
    c.ingest(avc(T + 60 * S, scontext_type="z_t", unit_at_receipt=None, cgroup_at_receipt=None))
    assert len(c) == 2  # boundary inclusive
    c.tick(T + 60 * S + 1)
    assert len(c) == 1


# --- PSI -------------------------------------------------------------------

WHEN = PsiWhen("memory", "some", 150_000, 1_000_000, 10.0, ("batch-*.service",))


def psi(
    ts: int, triggered: bool = True, cgroup: str = "system.slice/batch-1.service", **kw: Any
) -> PsiEvent:
    fields: dict[str, Any] = {
        "resource": "memory",
        "kind": "some",
        "avg10": 20.0,
        "avg60": 5.0,
        "avg300": 1.0,
        "total_us": 1,
        "triggered": triggered,
        "stall_us": 150_000 if triggered else None,
        "window_us": 1_000_000 if triggered else None,
    }
    fields.update(kw)
    return PsiEvent(ts_us=ts, cgroup=cgroup, **fields)


def psi_run(c: Correlator, clock: Clock, start: int, seconds: int, **kw: Any) -> list[Any]:
    out = []
    for i in range(seconds + 1):
        clock.now_us = start + i * S
        out += c.ingest(psi(start + i * S, **kw))
    return out


def test_psi_sustained_threshold() -> None:
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN], clock)
    assert psi_run(c, clock, T, 9) == []
    [inc] = c.ingest(psi(T + 10 * S))
    assert inc.kind == "psi"
    assert inc.target == "system.slice/batch-1.service"
    assert inc.ts_us == T + 10 * S
    assert inc.sustained == 10.0


def test_psi_each_sustained_value_fires_at_its_own_time() -> None:
    clock = Clock()
    long = PsiWhen("memory", "some", 150_000, 1_000_000, 30.0, ("batch-*.service",))
    c = Correlator(CorrelationConfig(), [WHEN, long, WHEN], clock)
    fired = {}
    for i in range(41):
        clock.now_us = T + i * S
        for inc in c.ingest(psi(T + i * S)):
            fired[inc.sustained] = inc.ts_us
    assert fired == {10.0: T + 10 * S, 30.0: T + 30 * S}


def test_psi_incident_matches_only_its_own_threshold_policy() -> None:
    fast = Policy("fast", "enforce", 0, WHEN, (Notify(),), Path("p.toml"))
    slow_when = PsiWhen("memory", "some", 500_000, 1_000_000, 10.0, ("batch-*.service",))
    slow = Policy("slow", "enforce", 0, slow_when, (Notify(),), Path("p.toml"))
    engine = PolicyEngine([fast, slow], lambda: 0.0)
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN, slow_when], clock)
    assert psi_run(c, clock, T, 9) == []
    [inc_fast] = c.ingest(psi(T + 10 * S))
    assert [p.name for p, _ in engine.plan(inc_fast)] == ["fast"]
    assert psi_run(c, clock, T, 9, stall_us=500_000) == []
    [inc_slow] = c.ingest(psi(T + 10 * S, stall_us=500_000))
    assert [p.name for p, _ in engine.plan(inc_slow)] == ["slow"]


def test_psi_one_incident_per_episode_then_rearm() -> None:
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN], clock)
    assert len(psi_run(c, clock, T, 30)) == 1
    # gap of max(2 * window, 2 s) = 2 s keeps the episode latched
    assert psi_run(c, clock, T + 32 * S, 20) == []
    # a longer quiet spell re-arms
    c.tick(T + 60 * S)
    assert len(psi_run(c, clock, T + 60 * S, 10)) == 1


def test_psi_gap_restarts_episode() -> None:
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN], clock)
    assert psi_run(c, clock, T, 8) == []
    assert psi_run(c, clock, T + 11 * S, 9) == []  # 3 s gap: new episode, only 9 s long
    assert len(c.ingest(psi(T + 21 * S))) == 1


def test_psi_unmatched_events_ignored() -> None:
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN], clock)
    assert psi_run(c, clock, T, 15, cgroup="system.slice/web.service") == []
    assert psi_run(c, clock, T, 15, stall_us=100_000) == []
    assert psi_run(c, clock, T, 15, resource="cpu") == []
    assert psi_run(c, clock, T, 15, triggered=False) == []


def test_psi_incident_carries_latest_samples_for_cgroup_and_parents() -> None:
    clock = Clock()
    c = Correlator(CorrelationConfig(), [WHEN], clock)
    parent = psi(T, triggered=False, cgroup="system.slice")
    own_old = psi(T, triggered=False, avg10=1.0)
    own = psi(T + S, triggered=False, avg10=2.0)
    sibling = psi(T, triggered=False, cgroup="system.slice/batch-10.service")
    for e in (parent, own_old, own, sibling):
        c.ingest(e)
    [inc] = psi_run(c, clock, T, 10)
    assert set(inc.related) == {parent, own}


# --- AVC bursts ------------------------------------------------------------


def test_avc_burst_then_latched_for_retention() -> None:
    clock = Clock()
    c = correlator(clock)
    for i in range(4):
        assert c.ingest(avc(T + i * 1_000_000, serial=i)) == []
    [inc] = c.ingest(avc(T + 4 * S, serial=4))
    assert inc.kind == "avc"
    assert inc.target == "httpd_t"
    assert len(inc.related) == 4
    assert c.ingest(avc(T + 5 * S, serial=5)) == []
    clock.now_us = T + 70 * S
    for i in range(4):
        assert c.ingest(avc(T + 66 * S + i, serial=10 + i)) == []
    assert len(c.ingest(avc(T + 66 * S + 4, serial=14))) == 1


def test_avc_burst_requires_window_and_same_type() -> None:
    c = correlator()
    for i in range(5):
        assert c.ingest(avc(T + i * 2 * S, serial=i)) == []  # spread over 8 s > before
    for i in range(4):
        c.ingest(avc(T + 9 * S, serial=20 + i, scontext_type=f"t{i}_t"))
    assert c.ingest(avc(T + 9 * S, serial=30, denied=False)) == []


def test_configure_keeps_pending_failures() -> None:
    clock = Clock()
    c = correlator(clock)
    c.ingest(failed(T))
    c.configure(CorrelationConfig(after=3.0), [])
    assert c.tick(T + 2 * S) == []  # the new, longer `after` applies to the pending one
    assert len(c.tick(T + 3 * S)) == 1


def test_failure_waits_for_the_audit_stream_to_catch_up() -> None:
    c = correlator()
    c.ingest(failed(T))
    # the after window has closed, but audit has only been read up to T
    assert c.tick(T + 2 * S, audit_until_us=T) == []
    late = avc(T - S // 2)  # read 8 s late under load, still within the window
    c.ingest(late)
    [inc] = c.tick(T + 3 * S, audit_until_us=T + 3 * S)
    assert [x.avc for x in inc.correlations] == [late]
    assert inc.audit_caught_up


def test_failure_is_finalised_anyway_once_audit_is_too_far_behind() -> None:
    c = correlator()
    c.ingest(failed(T))
    hi = T + S  # failure + after
    assert c.tick(hi + AUDIT_WAIT_MAX_US - 1, audit_until_us=T) == []
    [inc] = c.tick(hi + AUDIT_WAIT_MAX_US, audit_until_us=T)
    assert not inc.audit_caught_up


def test_without_an_audit_watermark_timing_is_unchanged() -> None:
    c = correlator()
    c.ingest(failed(T))
    [inc] = c.tick(T + S)
    assert inc.audit_caught_up


def test_dead_main_process_matches_by_pid() -> None:
    gone = avc(T - S, pid=4242, cgroup_at_receipt=None, unit_at_receipt=None, comm="x", exe="/x")
    c = score(gone, "web.service", None, set(), main_pid=4242)
    assert c is not None
    assert c.reasons == ("pid was the unit's main process",)
    assert c.confidence == pytest.approx(0.9)
    assert score(gone, "web.service", None, set(), main_pid=4243) is None


def test_main_pid_from_unit_info_is_used_at_finalisation() -> None:
    def info(unit: str) -> tuple[set[str], str | None, int | None]:
        return set(), None, 4242

    c = correlator(unit_info=info)
    c.ingest(avc(T - S, pid=4242, cgroup_at_receipt=None, unit_at_receipt=None))
    c.ingest(failed(T))
    [inc] = c.tick(T + S)
    assert inc.correlations[0].reasons == ("pid was the unit's main process",)
