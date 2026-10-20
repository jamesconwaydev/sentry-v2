"""Helpers shared by the sink tests: bundles, fake time, a self-signed cert, an HTTPS server."""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentry_v2.ids import uuid7


def make_bundle(**overrides: Any) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "schema": "sentry-v2/bundle/1",
        "id": uuid7(),
        "ts": "2026-10-14T12:00:00.123456Z",
        "severity": "warning",
        "host": {"hostname": "web1"},
        "trigger": {"kind": "psi", "unit": "nginx.service"},
        "incident": {"target": "nginx.service"},
        "decision": {"policy": "nginx-memory", "mode": "dry-run", "actions": []},
    }
    bundle.update(overrides)
    return bundle


class FakeTime:
    """A clock and an async sleep that advances it instantly."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_cert(dest: Path) -> tuple[Path, Path] | None:
    """Write a self-signed cert for 127.0.0.1/localhost; None if no tool can make one."""
    cert, key = dest / "cert.pem", dest / "key.pem"
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError:
        if not (openssl := shutil.which("openssl")):
            return None
        subprocess.run(  # noqa: S603
            [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "2", "-subj", "/CN=localhost", "-keyout", str(key),
             "-out", str(cert), "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )  # fmt: skip
        return cert, key
    pk = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    san = x509.SubjectAlternativeName(
        [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    )
    c = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(pk, hashes.SHA256())
    )
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        pk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, key


@dataclass
class Request:
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HttpsServer:
    url: str
    requests: list[Request] = field(default_factory=list)
    status: int = 200
    reply: bytes = b"{}"


def serve_https(cert: Path, key: Path, port: int = 0) -> Iterator[HttpsServer]:
    """Run a recording HTTPS server in a thread for the life of the generator."""
    state = HttpsServer(url="")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state.requests.append(Request(self.path, dict(self.headers.items()), body))
            self.send_response(state.status)
            self.send_header("Content-Length", str(len(state.reply)))
            self.end_headers()
            self.wfile.write(state.reply)

        def log_message(self, *args: Any) -> None:
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    state.url = f"https://127.0.0.1:{srv.server_address[1]}"
    t = threading.Thread(target=srv.serve_forever, args=(0.02,), daemon=True)
    t.start()
    try:
        yield state
    finally:
        srv.shutdown()
        srv.server_close()
