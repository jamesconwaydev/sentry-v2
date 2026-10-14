import asyncio
import logging

import pytest

from sentry_v2.metrics import MetricsServer, Registry, build_registry


def test_counter_renders_two_label_sets_sorted():
    r = Registry()
    c = r.counter("x_total", "Things.", ("a", "b"))
    c.labels(a="z", b="1").inc()
    c.labels(a="y", b="2").inc(2)
    c.labels(a="y", b="2").inc()
    assert r.render() == (
        "# HELP x_total Things.\n"
        "# TYPE x_total counter\n"
        'x_total{a="y",b="2"} 3.0\n'
        'x_total{a="z",b="1"} 1.0\n'
    )


def test_unlabelled_and_gauge_values():
    r = Registry()
    g = r.gauge("g", "G.")
    c = r.counter("c_total", "C.")
    assert g.set(float("nan")) is None
    c.inc()
    assert (
        r.render()
        == "# HELP g G.\n# TYPE g gauge\ng NaN\n# HELP c_total C.\n# TYPE c_total counter\nc_total 1.0\n"
    )
    g.set(float("inf"))
    assert "g +Inf\n" in r.render()
    g.set(float("-inf"))
    assert "g -Inf\n" in r.render()


def test_labelled_metric_has_no_direct_inc():
    c = Registry().counter("c_total", "C.", ("a",))
    with pytest.raises(ValueError):
        c.inc()
    with pytest.raises(ValueError):
        c.labels(b="1")


def test_counter_rejects_negative():
    with pytest.raises(ValueError):
        Registry().counter("c_total", "C.").inc(-1)


def test_escaping():
    r = Registry()
    r.gauge("g", "a\\b\nc", ("l",)).labels(l='q"\\\n').set(1)
    assert r.render() == '# HELP g a\\\\b\\nc\n# TYPE g gauge\ng{l="q\\"\\\\\\n"} 1.0\n'


def test_duplicate_and_invalid_names():
    r = Registry()
    r.counter("a", "A")
    with pytest.raises(ValueError):
        r.gauge("a", "A")
    for bad in ("1a", "a-b", ""):
        with pytest.raises(ValueError):
            r.gauge(bad, "x")
    for bad in ("__x", "a:b", "1a"):
        with pytest.raises(ValueError):
            r.gauge("ok", "x", (bad,))


def test_gauge_func_evaluated_at_scrape():
    r = Registry()
    box = [1.0]
    r.gauge_func("f", "F.", lambda: [({"k": "b"}, box[0] + 1), ({"k": "a"}, 0.5)])
    box[0] = 4.0
    assert r.render() == '# HELP f F.\n# TYPE f gauge\nf{k="a"} 0.5\nf{k="b"} 5.0\n'


def test_gauge_func_duplicate():
    r = Registry()
    r.gauge("f", "F.")
    with pytest.raises(ValueError):
        r.gauge_func("f", "F.", lambda: [])


def test_build_registry():
    r, m = build_registry({"version": "1.2.3"})
    m.actions_total.labels(policy="p", action="freeze", mode="dry-run", result="ok").inc()
    m.incidents_total.labels(kind="unit_failed").inc()
    m.avc_correlated_total.inc()
    m.events_dropped_total.labels(collector="psi").inc()
    m.sink_failures_total.labels(sink="file").inc()
    out = r.render()
    assert 'sentry_v2_build_info{version="1.2.3"} 1.0\n' in out
    assert (
        'sentry_v2_actions_total{policy="p",action="freeze",mode="dry-run",result="ok"} 1.0\n'
        in out
    )
    assert "sentry_v2_avc_correlated_total 1.0\n" in out
    assert out.index("sentry_v2_actions_total") < out.index("sentry_v2_build_info")


async def _get(port: int, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


def _serve(raw: bytes, host: str = "127.0.0.1") -> bytes:
    async def go() -> bytes:
        r = Registry()
        r.counter("c_total", "C.").inc()
        s = MetricsServer(r, host, 0)
        await s.start()
        try:
            return await _get(s.port, raw)
        finally:
            await s.stop()

    return asyncio.run(go())


def test_server_metrics_ok():
    resp = _serve(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
    head, _, body = resp.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Type: text/plain; version=0.0.4; charset=utf-8" in head
    assert f"Content-Length: {len(body)}".encode() in head
    assert body == b"# HELP c_total C.\n# TYPE c_total counter\nc_total 1.0\n"


def test_server_404_and_405():
    assert _serve(b"GET / HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 404")
    assert _serve(b"GET /metrics?x=1 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 404")
    assert _serve(b"POST /metrics HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 405")
    assert _serve(b"garbage\r\n\r\n").startswith(b"HTTP/1.1 400")


def test_server_oversized_headers_closed():
    resp = _serve(b"GET /metrics HTTP/1.1\r\n" + b"X: " + b"a" * 8000 + b"\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 431")


def test_server_header_timeout():
    async def go() -> bytes:
        s = MetricsServer(Registry(), "127.0.0.1", 0, header_timeout=0.05)
        await s.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", s.port)
            writer.write(b"GET /metrics HTTP/1.1\r\n")
            await writer.drain()
            data = await reader.read()
            writer.close()
            return data
        finally:
            await s.stop()

    assert asyncio.run(go()).startswith(b"HTTP/1.1 408")


def test_non_loopback_host_warns(caplog):
    async def go() -> None:
        s = MetricsServer(Registry(), "0.0.0.0", 0)  # noqa: S104
        await s.start()
        await s.stop()

    with caplog.at_level(logging.WARNING):
        asyncio.run(go())
    assert "non-loopback" in caplog.text
