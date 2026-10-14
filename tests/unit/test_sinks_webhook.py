import asyncio
import hashlib
import hmac
import json
import socket
import ssl
from pathlib import Path

import pytest
from sinkfixtures import FakeTime, HttpsServer, make_bundle, serve_https

from sentry_v2.sinks.base import SinkError
from sentry_v2.sinks.http import post, tls_context
from sentry_v2.sinks.spool import Spool
from sentry_v2.sinks.webhook import WebhookSink

KEY = "k3y"


def _sink(url: str, ca: Path, spool: Path, t: FakeTime | None = None) -> WebhookSink:
    t = t or FakeTime()
    return WebhookSink(
        url,
        KEY,
        tls_context(ca),
        Spool(spool),
        sleep=t.sleep,
        clock=t.clock,
        random=lambda a, b: 1.0,
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_tls_context_is_strict(tls_cert: tuple[Path, Path]) -> None:
    ctx = tls_context(tls_cert[0])
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_post_rejects_untrusted_cert(https_server: HttpsServer) -> None:
    with pytest.raises(ssl.SSLError):
        post(https_server.url + "/", b"{}", {}, tls_context(None), 5)


def test_post_non_2xx_is_sink_error(https_server: HttpsServer, tls_cert: tuple[Path, Path]) -> None:
    https_server.status = 503
    with pytest.raises(SinkError) as e:
        post(https_server.url + "/x", b"{}", {}, tls_context(tls_cert[0]), 5)
    assert e.value.status == 503


def test_signature_recomputes(
    https_server: HttpsServer, tls_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    sink = _sink(https_server.url + "/hook?x=1", tls_cert[0], tmp_path)
    b = make_bundle()
    asyncio.run(sink.send(b))
    (req,) = https_server.requests
    assert req.path == "/hook?x=1"
    ts = req.headers["X-Sentry-V2-Timestamp"]
    want = hmac.new(KEY.encode(), f"{ts}.".encode() + req.body, hashlib.sha256).hexdigest()
    assert req.headers["X-Sentry-V2-Signature"] == f"sha256={want}"
    assert req.headers["Content-Type"] == "application/json"
    assert json.loads(req.body) == b
    assert list(Spool(tmp_path).pending()) == []


def test_server_down_spools_then_restart_resends_in_order(
    tls_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    port = _free_port()
    url = f"https://127.0.0.1:{port}/hook"
    t = FakeTime()
    sink = _sink(url, tls_cert[0], tmp_path, t)
    bundles = [make_bundle() for _ in range(3)]
    for b in bundles:
        with pytest.raises(SinkError, match="giving up"):
            asyncio.run(sink.send(b))
    # backoff 1, 2, 4, ... capped at 3600, and the whole retry stays within an hour
    assert t.sleeps[:4] == [1, 2, 4, 8]
    assert sum(t.sleeps[:12]) <= 3600
    assert [x["id"] for _, x in Spool(tmp_path).pending()] == [b["id"] for b in bundles]

    for server in serve_https(*tls_cert, port=port):
        restarted = _sink(url, tls_cert[0], tmp_path)
        asyncio.run(restarted.flush())
        assert [json.loads(r.body)["id"] for r in server.requests] == [b["id"] for b in bundles]
    assert list(Spool(tmp_path).pending()) == []


def test_success_also_resends_older_spooled(
    https_server: HttpsServer, tls_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    old = make_bundle()
    Spool(tmp_path).push(old)
    new = make_bundle()
    asyncio.run(_sink(https_server.url, tls_cert[0], tmp_path).send(new))
    assert [json.loads(r.body)["id"] for r in https_server.requests] == [old["id"], new["id"]]


def test_client_error_is_dropped_not_retried(
    https_server: HttpsServer, tls_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    https_server.status = 400
    t = FakeTime()
    with pytest.raises(SinkError, match="rejected"):
        asyncio.run(_sink(https_server.url, tls_cert[0], tmp_path, t).send(make_bundle()))
    assert t.sleeps == []
    assert list(Spool(tmp_path).pending()) == []


def test_transient_error_retries_then_succeeds(
    https_server: HttpsServer, tls_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    https_server.status = 503
    t = FakeTime()
    sink = _sink(https_server.url, tls_cert[0], tmp_path, t)

    async def heal(seconds: float) -> None:
        t.sleeps.append(seconds)
        https_server.status = 200

    sink._sleep = heal
    asyncio.run(sink.send(make_bundle()))
    assert len(https_server.requests) == 2
    assert t.sleeps == [1]
