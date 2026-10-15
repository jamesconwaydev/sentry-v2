import asyncio
import json
import os
import shutil
import socket
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentry_v2 import control
from sentry_v2.control import CommandError, ControlServer, Peer, peer_groups


@pytest.fixture
def sock_path() -> Iterator[Path]:
    # AF_UNIX paths are capped at ~104 bytes; pytest's tmp_path can be longer
    d = tempfile.mkdtemp(prefix="sv2-")
    yield Path(d) / "run" / "control.sock"
    shutil.rmtree(d)


class Client:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer

    @classmethod
    async def open(cls, path: Path) -> "Client":
        return cls(*await asyncio.open_unix_connection(str(path), limit=1 << 20))

    async def send_raw(self, data: bytes) -> dict:
        self.writer.write(data)
        await self.writer.drain()
        return await self.recv()

    async def recv(self) -> dict:
        line = await asyncio.wait_for(self.reader.readline(), 5)
        return json.loads(line) if line else {}

    async def call(self, cmd: str, **args: object) -> dict:
        return await self.send_raw(json.dumps({"id": 7, "cmd": cmd, "args": args}).encode() + b"\n")

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


async def echo(args: dict) -> dict:
    return {"echo": args}


async def boom(args: dict) -> dict:
    raise RuntimeError("secret detail")


async def refuse(args: dict) -> dict:
    raise CommandError("no such action")


HANDLERS = {"status": echo, "pause": echo, "boom": boom, "refuse": refuse}


def server(path: Path, peer: Peer | None = None, **kw: object) -> ControlServer:
    resolver = (lambda _sock: peer) if peer else control.peer_cred
    return ControlServer(
        path, HANDLERS, read_gid=None, admin_gid=None, mutating={"pause"},
        peer_cred=resolver, **kw,
    )  # fmt: skip


READ, ADMIN = os.getgid(), 999_999  # the socket is chgrp'd to READ, which must be ours


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 10))


def test_same_uid_client_can_read_and_mutate(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path)
        await srv.start()
        try:
            assert stat.S_IMODE(sock_path.stat().st_mode) == 0o600  # no group: root only
            c = await Client.open(sock_path)
            assert await c.call("status", x=1) == {
                "id": 7,
                "ok": True,
                "result": {"echo": {"x": 1}},
            }
            assert (await c.call("pause"))["ok"] is True
            await c.close()
        finally:
            await srv.stop()
        assert not sock_path.exists()

    run(main())


def test_mutation_from_reader_is_denied(sock_path: Path) -> None:
    async def main() -> None:
        srv = ControlServer(
            sock_path, HANDLERS, read_gid=READ, admin_gid=ADMIN, mutating={"pause"},
            peer_cred=lambda _s: Peer(pid=1, uid=1000, groups=frozenset({READ})),
        )  # fmt: skip
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert (await c.call("status"))["ok"] is True
            r = await c.call("pause")
            assert (r["id"], r["ok"]) == (7, False)
            assert r["error"].startswith("permission denied: pause needs uid 0 or group ")
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_admin_group_may_mutate_and_strangers_may_not_read(sock_path: Path) -> None:
    async def main() -> None:
        peers = iter([Peer(1, 1000, frozenset({ADMIN})), Peer(1, 1001, frozenset({9}))])
        srv = ControlServer(
            sock_path, HANDLERS, read_gid=READ, admin_gid=ADMIN, mutating={"pause"},
            peer_cred=lambda _s: next(peers),
        )  # fmt: skip
        await srv.start()
        try:
            admin = await Client.open(sock_path)
            assert (await admin.call("pause"))["ok"] is True
            stranger = await Client.open(sock_path)
            assert (await stranger.call("status"))["error"].startswith("permission denied")
            await admin.close()
            await stranger.close()
        finally:
            await srv.stop()

    run(main())


def test_socket_group_and_mode(sock_path: Path) -> None:
    async def main() -> None:
        gid = os.getgid()
        srv = ControlServer(sock_path, HANDLERS, read_gid=gid, admin_gid=None, mutating=set())
        await srv.start()
        try:
            st = sock_path.stat()
            assert (stat.S_IMODE(st.st_mode), st.st_gid) == (0o660, gid)
        finally:
            await srv.stop()

    run(main())


def test_stale_socket_is_replaced(sock_path: Path) -> None:
    sock_path.parent.mkdir(parents=True)
    sock_path.write_text("stale")

    async def main() -> None:
        srv = server(sock_path)
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert (await c.call("status"))["ok"] is True
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_bad_requests_get_errors_and_connection_stays_open(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path, Peer(1, 0, frozenset()))
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert (await c.send_raw(b"{nope\n"))["error"] == "malformed JSON"
            assert (await c.send_raw(b"[1]\n"))["error"] == "request must be an object"
            assert (await c.send_raw(b'{"id": 1}\n'))["error"] == "cmd must be a string"
            r = await c.send_raw(b'{"id": 2, "cmd": "status", "args": 3}\n')
            assert r == {"id": 2, "ok": False, "error": "args must be an object"}
            assert (await c.call("nope"))["error"] == "unknown command 'nope'"
            assert (await c.call("refuse"))["error"] == "no such action"
            assert (await c.call("boom"))["error"] == "internal error"
            assert (await c.send_raw(b"\n"))["error"] == "malformed JSON"
            # still usable after all of that
            r = await c.send_raw(b'{"id": "a", "cmd": "status"}\n')
            assert r == {"id": "a", "ok": True, "result": {"echo": {}}}
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_oversize_line_is_refused_and_closed(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path, Peer(1, 0, frozenset()))
        await srv.start()
        try:
            c = await Client.open(sock_path)
            r = await c.send_raw(b"x" * (control.MAX_LINE + 10) + b"\n")
            assert r == {"id": None, "ok": False, "error": "request too large"}
            assert await c.reader.read() == b""  # closed
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_idle_connection_is_closed(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path, Peer(1, 0, frozenset()), idle_timeout=0.05)
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert await asyncio.wait_for(c.reader.read(), 2) == b""
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_connection_caps(sock_path: Path) -> None:
    async def main() -> None:
        peers = iter(
            [
                Peer(1, 1000, frozenset({READ})),  # uid 1000: 1 of 2 allowed
                Peer(1, 1000, frozenset({READ})),  # uid 1000: 2 of 2
                Peer(1, 1000, frozenset({READ})),  # over the per-uid cap
                Peer(1, 1001, frozenset({READ})),  # 3 of 3 overall
                Peer(1, 1002, frozenset({READ})),  # over the global cap
                Peer(1, 0, frozenset()),  # root is never capped
                Peer(1, 1003, frozenset({ADMIN})),  # nor is the admin group
            ]
        )
        srv = ControlServer(
            sock_path, HANDLERS, read_gid=READ, admin_gid=ADMIN, mutating=set(),
            peer_cred=lambda _s: next(peers), max_connections=3, max_per_uid=2,
        )  # fmt: skip
        await srv.start()
        try:
            clients = []
            for expect_ok in (True, True, False, True, False, True, True):
                c = await Client.open(sock_path)
                if expect_ok:
                    assert (await c.call("status"))["ok"] is True
                else:
                    assert (await c.recv())["error"] == "too many connections"
                    assert await c.reader.read() == b""
                clients.append(c)
            await clients[0].close()  # frees one of uid 1000's slots
            for _ in range(100):
                if srv._per_uid[1000] == 1:
                    break
                await asyncio.sleep(0.01)
            assert dict(srv._per_uid) == {1000: 1, 1001: 1}
            for c in clients[1:]:
                await c.close()
        finally:
            await srv.stop()

    run(main())


def test_subscribe_streams_events_until_disconnect(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path, Peer(1, 0, frozenset()))
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert await c.call("subscribe") == {
                "id": 7,
                "ok": True,
                "result": {"subscribed": True},
            }
            srv.publish({"type": "incident", "incident": {"id": "x"}})
            assert await c.recv() == {"event": {"type": "incident", "incident": {"id": "x"}}}
            await c.close()
            for _ in range(100):
                if not srv.subscribers:
                    break
                await asyncio.sleep(0.01)
            assert srv.subscribers == 0
            srv.publish({"type": "noop"})  # nobody listening: fine
        finally:
            await srv.stop()

    run(main())


def test_subscribe_needs_read_access(sock_path: Path) -> None:
    async def main() -> None:
        srv = ControlServer(
            sock_path, HANDLERS, read_gid=READ, admin_gid=None, mutating=set(),
            peer_cred=lambda _s: Peer(1, 1000, frozenset()),
        )  # fmt: skip
        await srv.start()
        try:
            c = await Client.open(sock_path)
            assert (await c.call("subscribe"))["error"].startswith("permission denied")
            await c.close()
        finally:
            await srv.stop()

    run(main())


def test_stop_closes_subscribers(sock_path: Path) -> None:
    async def main() -> None:
        srv = server(sock_path, Peer(1, 0, frozenset()))
        await srv.start()
        c = await Client.open(sock_path)
        await c.call("subscribe")
        await srv.stop()
        assert await asyncio.wait_for(c.reader.read(), 2) == b""
        await c.close()

    run(main())


def test_peer_cred_of_real_socket() -> None:
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        peer = control.peer_cred(a)
        assert peer.uid == os.geteuid()
        assert os.getegid() in peer.groups
    finally:
        a.close()
        b.close()


def test_peer_groups_reads_proc_status(tmp_path: Path) -> None:
    (tmp_path / "42").mkdir()
    (tmp_path / "42" / "status").write_text("Name:\tx\nGroups:\t10 20 \nUid:\t0\n")
    assert peer_groups(42, 5, tmp_path) == frozenset({5, 10, 20})
    assert peer_groups(43, 5, tmp_path) == frozenset({5})  # process gone
