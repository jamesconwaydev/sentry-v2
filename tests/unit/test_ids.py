import uuid

from sentry_v2 import ids
from sentry_v2.events import AvcEvent, Correlation, Incident, PsiEvent, UnitEvent


def test_uuid7_version_variant_and_order() -> None:
    values = [ids.uuid7() for _ in range(5000)]
    parsed = [uuid.UUID(v) for v in values]
    assert all(p.version == 7 and p.variant == uuid.RFC_4122 for p in parsed)
    assert values == sorted(values)
    assert len(set(values)) == len(values)


def test_uuid7_counter_overflow_advances_timestamp(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ids.time, "time_ns", lambda: 0)
    ids._last_ms = 10**12
    ids._counter = 0xFFF
    a = ids.uuid7()
    assert (uuid.UUID(a).int >> 80) == 10**12 + 1


def test_event_to_dict_round_trip() -> None:
    avc = AvcEvent(
        ts_us=2,
        serial=1,
        denied=True,
        perms=("read",),
        scontext="u:r:httpd_t:s0",
        scontext_type="httpd_t",
        tcontext="u:o:etc_t:s0",
        tclass="file",
    )
    unit = UnitEvent(ts_us=3, unit="a.service", kind="failed", result="watchdog")
    psi = PsiEvent(
        ts_us=1,
        cgroup="/",
        resource="cpu",
        kind="some",
        avg10=1.0,
        avg60=0.5,
        avg300=0.1,
        total_us=5,
        triggered=True,
    )
    inc = Incident(
        "id", "unit_failed", 3, "a.service", unit, (avc, psi), (Correlation(avc, 0.9, ("cgroup",)),)
    )
    d = inc.to_dict()
    assert d["kind"] == "unit_failed"
    assert d["correlations"][0]["avc"]["perms"] == ("read",)  # type: ignore[index]
    assert avc.to_dict()["scontext_type"] == "httpd_t"
    assert psi.to_dict()["triggered"] is True
