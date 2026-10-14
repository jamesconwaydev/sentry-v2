import json

from sentry_v2.events import AvcEvent, Correlation, Incident, PsiEvent, UnitEvent


def test_event_to_dict() -> None:
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
        stall_us=150000,
        window_us=1000000,
    )
    inc = Incident(
        "id", "unit_failed", 3, "a.service", unit, (avc, psi), (Correlation(avc, 0.9, ("cgroup",)),)
    )
    d = inc.to_dict()
    assert d["kind"] == "unit_failed"
    assert d["sustained"] is None
    psi_inc = Incident("id", "psi", 3, "/", psi, (), (), 10.0)
    assert json.loads(json.dumps(psi_inc.to_dict()))["sustained"] == 10.0
    assert d["correlations"][0]["avc"]["perms"] == ("read",)  # type: ignore[index]
    assert AvcEvent(**avc.to_dict()) == avc  # type: ignore[arg-type]
    assert json.loads(json.dumps(inc.to_dict()))["trigger"]["unit"] == "a.service"
    assert avc.to_dict()["scontext_type"] == "httpd_t"
    assert psi.to_dict()["triggered"] is True
