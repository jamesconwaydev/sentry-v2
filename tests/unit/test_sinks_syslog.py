import asyncio
import json
import re
import socket
import ssl
import threading
from pathlib import Path

from sinkfixtures import make_bundle

from sentry_v2.sinks.http import tls_context
from sentry_v2.sinks.syslog import SyslogSink, format_message

RFC5424 = re.compile(
    r"<(?P<pri>\d+)>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) - (?P<msgid>\S+) "
    r"\[sentry-v2@32473(?P<params>(?: \w+=\"(?:[^\"\\\]]|\\.)*\")*)\] (?P<msg>.*)",
    re.DOTALL,
)


def _params(sd: str) -> dict[str, str]:
    return {
        k: re.sub(r"\\(.)", r"\1", v) for k, v in re.findall(r'(\w+)="((?:[^"\\\]]|\\.)*)"', sd)
    }


def test_format_has_pri_sd_and_json() -> None:
    b = make_bundle(severity="critical", incident={"target": 'we"ird\\unit]'})
    m = RFC5424.fullmatch(format_message(b, "web1", "sentry-v2").decode())
    assert m
    assert m["pri"] == str(3 * 8 + 2)
    assert (m["ts"], m["host"], m["app"], m["msgid"]) == (b["ts"], "web1", "sentry-v2", "BUNDLE")
    assert 'unit="we\\"ird\\\\unit\\]"' in m["params"]
    assert _params(m["params"]) == {
        "id": b["id"],
        "severity": "critical",
        "policy": "nginx-memory",
        "unit": 'we"ird\\unit]',
    }
    assert json.loads(m["msg"]) == b


def test_severity_mapping_and_missing_fields() -> None:
    b = make_bundle(severity="info", decision={"policy": None})
    del b["incident"]
    m = RFC5424.fullmatch(format_message(b, "h", "a").decode())
    assert m
    assert m["pri"] == "30"
    assert _params(m["params"]).keys() == {"id", "severity"}
    pri = RFC5424.fullmatch(format_message(make_bundle(), "h", "a").decode())
    assert pri and pri["pri"] == "28"


def test_udp_receives_parseable_message() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(5)
        sink = SyslogSink("127.0.0.1", srv.getsockname()[1], "udp", hostname="web1")
        b = make_bundle()
        asyncio.run(sink.send(b))
        m = RFC5424.fullmatch(srv.recv(65535).decode())
    assert m and json.loads(m["msg"]) == b


def test_udp_truncates_large_messages() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(5)
        sink = SyslogSink("127.0.0.1", srv.getsockname()[1], "udp", hostname="web1")
        asyncio.run(sink.send(make_bundle(context={"journal": ["x" * 100] * 200})))
        data = srv.recv(65535)
    assert len(data) == 8192
    m = RFC5424.fullmatch(data.decode())
    assert m and _params(m["params"])["truncated"] == "1"


def _accept_one(srv: socket.socket, out: list[bytes], ctx: ssl.SSLContext | None) -> None:
    conn, _ = srv.accept()
    if ctx:
        conn = ctx.wrap_socket(conn, server_side=True)
    with conn:
        buf = b""
        while chunk := conn.recv(65536):
            buf += chunk
    out.append(buf)


def _stream(transport: str, ctx_server: ssl.SSLContext | None, ca: Path | None) -> bytes:
    with socket.create_server(("127.0.0.1", 0)) as srv:
        srv.settimeout(5)
        out: list[bytes] = []
        t = threading.Thread(target=_accept_one, args=(srv, out, ctx_server))
        t.start()
        sink = SyslogSink(
            "127.0.0.1",
            srv.getsockname()[1],
            transport,  # type: ignore[arg-type]
            context=tls_context(ca) if ca else None,
            hostname="web1",
        )
        b = make_bundle(context={"journal": ["y" * 100] * 200})
        asyncio.run(sink.send(b))
        t.join(5)
    (data,) = out
    return data


def test_tcp_octet_counting_exact() -> None:
    data = _stream("tcp", None, None)
    length, _, frame = data.partition(b" ")
    assert int(length) == len(frame) > 8192
    m = RFC5424.fullmatch(frame.decode())
    assert m and "truncated" not in m["params"]
    assert json.loads(m["msg"])["context"]["journal"][0] == "y" * 100


def test_tls_octet_counting(tls_cert: tuple[Path, Path]) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*tls_cert)
    data = _stream("tls", ctx, tls_cert[0])
    length, _, frame = data.partition(b" ")
    assert int(length) == len(frame)
    assert RFC5424.fullmatch(frame.decode())
