import asyncio
import base64
import json
from pathlib import Path

import pytest
from sinkfixtures import HttpsServer, make_bundle

from sentry_v2.sinks.base import SinkError
from sentry_v2.sinks.elastic import ElasticSink
from sentry_v2.sinks.http import tls_context
from sentry_v2.sinks.splunk import SplunkHecSink


def test_hec_body_and_auth(https_server: HttpsServer, tls_cert: tuple[Path, Path]) -> None:
    sink = SplunkHecSink(https_server.url + "/", "tok", "sentry", tls_context(tls_cert[0]))
    b = make_bundle(ts="2026-10-14T12:00:00.5Z")
    asyncio.run(sink.send(b))
    (req,) = https_server.requests
    assert req.path == "/services/collector/event"
    assert req.headers["Authorization"] == "Splunk tok"
    assert json.loads(req.body) == {
        "event": b,
        "sourcetype": "sentry-v2:bundle",
        "time": 1791979200.5,
        "index": "sentry",
    }


def test_hec_full_endpoint_url_and_no_index(
    https_server: HttpsServer, tls_cert: tuple[Path, Path]
) -> None:
    url = https_server.url + "/services/collector/event"
    asyncio.run(SplunkHecSink(url, "tok", None, tls_context(tls_cert[0])).send(make_bundle()))
    (req,) = https_server.requests
    assert req.path == "/services/collector/event"
    assert "index" not in json.loads(req.body)


def test_elastic_bulk_ndjson_with_api_key(
    https_server: HttpsServer, tls_cert: tuple[Path, Path]
) -> None:
    https_server.reply = b'{"errors":false,"items":[{"create":{"status":201}}]}'
    sink = ElasticSink(https_server.url, "sentry-v2", "ApiKey abc", tls_context(tls_cert[0]))
    b = make_bundle()
    asyncio.run(sink.send(b))
    (req,) = https_server.requests
    assert req.path == "/_bulk"
    assert req.headers["Authorization"] == "ApiKey abc"
    assert req.headers["Content-Type"] == "application/x-ndjson"
    assert req.body.endswith(b"\n")
    action, doc = (json.loads(line) for line in req.body.decode().splitlines())
    assert action == {"create": {"_index": "sentry-v2"}}
    assert doc == {**b, "@timestamp": b["ts"]}


def test_elastic_item_error_is_failure(
    https_server: HttpsServer, tls_cert: tuple[Path, Path]
) -> None:
    https_server.reply = (
        b'{"errors":true,"items":[{"create":{"status":409,"error":{"type":"conflict"}}}]}'
    )
    sink = ElasticSink(https_server.url, "i", "ApiKey abc", tls_context(tls_cert[0]))
    with pytest.raises(SinkError, match="conflict") as e:
        asyncio.run(sink.send(make_bundle()))
    assert e.value.status == 409


def test_elastic_basic_auth_header() -> None:
    assert ElasticSink.basic("elastic", "pw") == "Basic " + base64.b64encode(b"elastic:pw").decode()
