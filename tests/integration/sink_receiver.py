"""Stands in for the sinks' endpoints; test_sinks.py runs it in sentry-test.slice.

    sink_receiver.py <log> <cert> <key>

Listens on the ports a real webhook, Splunk HEC, Elasticsearch and syslog
collector use on 127.0.0.1, and appends what arrives to `log` as JSON lines.
"""

from __future__ import annotations

import base64
import http.server
import json
import socket
import socketserver
import ssl
import sys
import threading
from typing import Any

log_path, cert, key = sys.argv[1:]
lock = threading.Lock()


def record(port: int, body: bytes, **extra: Any) -> None:
    line = {"port": port, "body": base64.b64encode(body).decode(), **extra}
    with lock, open(log_path, "a") as f:
        f.write(json.dumps(line) + "\n")


class Http(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        record(self.server.server_port, body, path=self.path, headers=dict(self.headers))
        reply = b'{"errors":false}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class Stream(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        record(self.server.server_port, self.rfile.read())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    @property
    def server_port(self) -> int:
        return self.server_address[1]

    def get_request(self) -> tuple[socket.socket, Any]:
        conn, addr = super().get_request()
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            conn = ctx.wrap_socket(conn, server_side=True)
        return conn, addr

    use_tls = False


class TlsServer(Server):
    use_tls = True


def udp(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", port))
        while True:
            record(port, s.recv(65535))


servers = [
    TlsServer(("127.0.0.1", 8443), Http),  # webhook, http_port_t
    TlsServer(("127.0.0.1", 8088), Http),  # Splunk HEC, unlabelled
    TlsServer(("127.0.0.1", 9200), Http),  # Elasticsearch, wap_wsp_port_t
    Server(("127.0.0.1", 601), Stream),  # syslog over TCP, syslogd_port_t
    TlsServer(("127.0.0.1", 6514), Stream),  # syslog over TLS, syslog_tls_port_t
]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
udp(514)  # syslog over UDP, syslogd_port_t
