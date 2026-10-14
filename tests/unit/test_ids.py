import uuid

from sentry_v2 import ids


def test_uuid7_version_variant_and_order() -> None:
    values = [ids.uuid7() for _ in range(5000)]
    parsed = [uuid.UUID(v) for v in values]
    assert all(p.version == 7 and p.variant == uuid.RFC_4122 for p in parsed)
    assert values == sorted(values)
    assert len(set(values)) == len(values)


def test_uuid7_counter_overflow_advances_timestamp(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ids.time, "time_ns", lambda: 0)
    monkeypatch.setattr(ids, "_last_ms", 10**12)
    monkeypatch.setattr(ids, "_counter", 0xFFF)
    a = ids.uuid7()
    assert (uuid.UUID(a).int >> 80) == 10**12 + 1
