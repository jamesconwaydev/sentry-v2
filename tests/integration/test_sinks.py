"""Every outbound sink gets a bundle out of the confined daemon, on its usual port.

sink_receiver.py plays the endpoints, so this proves the daemon's SELinux
policy, TLS verification and wire format, not that a Splunk or Elasticsearch
of any given version accepts the result. A refused connection shows up here
as a missing delivery and in test_no_denials_for_the_daemon as a denial.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import ctl, sh, wait_for

pytestmark = pytest.mark.integration

CONFIG = Path("/etc/sentry-v2/sentry-v2.toml")
SECRETS = Path("/etc/sentry-v2/itest-sinks")
HMAC_KEY = "itest-hmac-key"
HEC_TOKEN = "itest-hec-token"  # noqa: S105
ES_KEY = "itest-es-key"

HTTP_SINKS = f"""
[sinks.webhook]
url = "https://localhost:8443/hook"
hmac_key_file = "{SECRETS}/hmac"
ca_file = "{SECRETS}/ca.pem"

[sinks.splunk_hec]
url = "https://localhost:8088"
token_file = "{SECRETS}/hec"
ca_file = "{SECRETS}/ca.pem"

[sinks.elastic]
url = "https://localhost:9200"
index = "sentry-v2"
api_key_file = "{SECRETS}/es"
ca_file = "{SECRETS}/ca.pem"
"""


@pytest.fixture(scope="module")
def secrets() -> Iterator[Path]:
    """The CA and secret files, labelled for the daemon. Yields the server's cert directory."""
    with tempfile.TemporaryDirectory(prefix="sv2-sinks-") as tmp:
        sh(
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=localhost", "-keyout", f"{tmp}/key.pem",
            "-out", f"{tmp}/cert.pem", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        )  # fmt: skip
        SECRETS.mkdir(mode=0o700)
        try:
            shutil.copy(f"{tmp}/cert.pem", SECRETS / "ca.pem")
            for name, value in (("hmac", HMAC_KEY), ("hec", HEC_TOKEN), ("es", ES_KEY)):
                (SECRETS / name).write_text(value)
                (SECRETS / name).chmod(0o600)
            sh("restorecon", "-R", str(SECRETS))
            yield Path(tmp)
        finally:
            shutil.rmtree(SECRETS)


@pytest.fixture
def receiver(secrets: Path, transient_unit: Callable[..., str]) -> Path:
    log = secrets / "received.jsonl"
    log.write_text("")
    script = Path(__file__).with_name("sink_receiver.py")
    transient_unit(
        "sink-receiver",
        ["/usr/bin/python3", str(script), str(log), f"{secrets}/cert.pem", f"{secrets}/key.pem"],
    )
    wait_for(lambda: ":6514" in sh("ss", "-ltn").stdout, 10, "the receiver to listen")
    return log


@pytest.fixture
def configure() -> Iterator[Callable[[str], None]]:
    """Add sink tables to the config and reload; puts the config back afterwards."""
    original = CONFIG.read_text()

    def apply(sinks: str) -> None:
        CONFIG.write_text(original + sinks)
        sh("systemctl", "reload", "sentry-v2")
        assert ctl("status")["last_reload_error"] is None

    try:
        yield apply
    finally:
        CONFIG.write_text(original)
        sh("systemctl", "reload", "sentry-v2", check=False)


def _deliveries(log: Path, port: int, unit: str) -> list[dict[str, Any]]:
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    hits = [e | {"raw": base64.b64decode(e["body"])} for e in entries if e["port"] == port]
    return [e for e in hits if unit.encode() in e["raw"]]


def _one_delivery(log: Path, port: int, unit: str) -> dict[str, Any]:
    return wait_for(
        lambda: next(iter(_deliveries(log, port, unit)), None), 30, f"a bundle on port {port}"
    )


def _sink_trouble() -> dict[str, Any]:
    sinks = ctl("status")["sinks"]
    return {k: v for k, v in sinks.items() if any(v.values())}


def test_https_sinks_deliver(
    receiver: Path, configure: Callable[[str], None], transient_unit: Callable[..., str]
) -> None:
    configure(HTTP_SINKS)
    unit = transient_unit("avc", ["/usr/bin/false"])

    hook = _one_delivery(receiver, 8443, unit)
    bundle = json.loads(hook["raw"])
    assert bundle["incident"]["target"] == unit
    signed = f"{hook['headers']['X-Sentry-V2-Timestamp']}.".encode() + hook["raw"]
    digest = hmac.new(HMAC_KEY.encode(), signed, hashlib.sha256).hexdigest()
    assert hook["headers"]["X-Sentry-V2-Signature"] == f"sha256={digest}"

    hec = _one_delivery(receiver, 8088, unit)
    assert hec["path"] == "/services/collector/event"
    assert hec["headers"]["Authorization"] == f"Splunk {HEC_TOKEN}"
    assert json.loads(hec["raw"])["event"]["id"] == bundle["id"]

    es = _one_delivery(receiver, 9200, unit)
    assert es["path"] == "/_bulk"
    assert es["headers"]["Authorization"] == f"ApiKey {ES_KEY}"
    action, doc = es["raw"].splitlines()
    assert json.loads(action)["create"] == {"_index": "sentry-v2", "_id": bundle["id"]}
    assert json.loads(doc)["@timestamp"] == bundle["ts"]

    assert not _sink_trouble()


@pytest.mark.parametrize(
    ("transport", "port", "extra"),
    [
        ("udp", 514, ""),
        ("tcp", 601, ""),
        ("tls", 6514, f'ca_file = "{SECRETS}/ca.pem"\n'),
    ],
)
def test_syslog_delivers(
    receiver: Path,
    configure: Callable[[str], None],
    transient_unit: Callable[..., str],
    transport: str,
    port: int,
    extra: str,
) -> None:
    configure(
        f'\n[sinks.syslog]\nhost = "127.0.0.1"\nport = {port}\ntransport = "{transport}"\n{extra}'
    )
    unit = transient_unit("avc", ["/usr/bin/false"])

    raw = _one_delivery(receiver, port, unit)["raw"].decode()
    assert re.search(r"<\d+>1 \S+ \S+ sentry-v2 - BUNDLE \[sentry-v2@32473 ", raw)
    if transport != "udp":  # RFC 6587 octet counting
        length, _, line = raw.partition(" ")
        assert int(length) == len(line.encode())
    assert not _sink_trouble()


def test_bad_certificate_is_refused(
    receiver: Path, configure: Callable[[str], None], transient_unit: Callable[..., str]
) -> None:
    """A server the CA file doesn't vouch for gets no bundle: the failure is counted instead."""
    configure(
        f'\n[sinks.splunk_hec]\nurl = "https://localhost:8088"\ntoken_file = "{SECRETS}/hec"\n'
    )  # system CAs only, and they don't know this server's cert
    unit = transient_unit("avc", ["/usr/bin/false"])
    wait_for(lambda: _sink_trouble().get("failures"), 30, "the sink failure to be counted")
    assert not _deliveries(receiver, 8088, unit)
