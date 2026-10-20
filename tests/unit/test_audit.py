import asyncio
import base64
import errno
import socket
import struct
import sys
import time
from pathlib import Path

import pytest

from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.collectors.audit import (
    AuditCollector,
    AuditRecord,
    AvcAssembler,
    LogTailSource,
    NetlinkSource,
    open_source,
    parse_audit_text,
    parse_netlink,
)
from sentry_v2.events import AvcEvent, EventQueue

FIX = Path(__file__).parent.parent / "fixtures" / "audit"
AVC_TEXT = (
    "audit(1792020144.848:918): avc:  denied  { entrypoint } for  pid=6844 "
    'comm="(cat)" path="/usr/bin/cat" dev="vda1" ino=41589 '
    "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:bin_t:s0 "
    "tclass=file permissive=0"
)


def nl(mtype: int, text: str) -> bytes:
    payload = text.encode() + b"\0"
    msg = struct.pack("=IHHII", 16 + len(payload), mtype, 0, 0, 0) + payload
    return msg + b"\0" * (-len(msg) % 4)


def rec(type_: str, serial: int, **f: str) -> AuditRecord:
    return AuditRecord(type_, serial * 1000, serial, f)


def avc(serial: int, **f: str) -> AuditRecord:
    base = {
        "verdict": "denied",
        "perms": "read",
        "pid": "7",
        "scontext": "a:b:httpd_t:s0",
        "tcontext": "a:b:x_t:s0",
        "tclass": "file",
    }
    return rec("AVC", serial, **(base | f))


def test_parse_avc_line():
    r = parse_audit_text("AVC", AVC_TEXT)
    assert r is not None and (r.serial, r.ts_us) == (918, 1792020144_848_000)
    ev = AvcAssembler()._build([r])[0]
    assert ev.perms == ("entrypoint",) and ev.denied and not ev.permissive
    assert ev.scontext_type == "httpd_t" and ev.tclass == "file" and ev.pid == 6844
    assert ev.comm == "(cat)"


def test_parse_garbage_and_user_avc_and_enriched():
    assert parse_audit_text("AVC", "nonsense") is None
    r = parse_audit_text(
        "USER_AVC",
        "audit(1.002:5): pid=900 uid=81 msg='avc:  granted  { send_msg acquire_svc } for "
        "spid=12 scontext=a:b:c_t:s0 tcontext=a:b:d_t:s0 tclass=dbus permissive=1'"
        "\x1dARCH=x86_64",
    )
    assert r is not None and r.ts_us == 1_002_000
    ev = AvcAssembler()._build([r])[0]
    assert (ev.denied, ev.permissive, ev.pid) == (False, True, 12)
    assert ev.perms == ("send_msg", "acquire_svc")


def test_hex_fields():
    r = parse_audit_text("PROCTITLE", "audit(1.0:1): proctitle=636174002F6574632F736861646F77")
    assert r is not None and r.fields["proctitle"] == "cat /etc/shadow"
    r = parse_audit_text("SYSCALL", 'audit(1.0:1): comm=636174 exe="/bin/cat" key=(null)')
    assert r is not None and r.fields["comm"] == "cat" and r.fields["exe"] == "/bin/cat"


def test_netlink_alignment():
    buf = nl(1400, "audit(1.0:1): abc") + nl(1320, "audit(1.0:1): ")
    assert len(nl(1400, "audit(1.0:1): abc")) % 4 == 0
    out = parse_netlink(buf)
    assert [t for t, _ in out] == [1400, 1320] and out[0][1] == "audit(1.0:1): abc"
    # unpadded odd-length first message still advances by the aligned length
    odd = struct.pack("=IHHII", 16 + 3, 1400, 0, 0, 0) + b"abc" + b"\0"
    assert [t for t, _ in parse_netlink(odd + nl(1320, "z"))] == [1400, 1320]
    assert parse_netlink(buf[:20]) == []  # truncated


def test_interleaved_serials():
    a = AvcAssembler()
    out = []
    for r, t in [
        (avc(10), 0),
        (avc(11), 0),
        (rec("SYSCALL", 10, comm="c10", exe="/e10"), 0),
        (rec("SYSCALL", 11, comm="c11", exe="/e11"), 0),
        (rec("EOE", 10), 0),
        (rec("EOE", 11), 0),
    ]:
        out += a.feed(r, t)
    assert [(e.serial, e.comm, e.exe) for e in out] == [(10, "c10", "/e10"), (11, "c11", "/e11")]


def test_flush_timeout_and_non_avc_dropped():
    a = AvcAssembler()
    assert a.feed(avc(1), 100.0) == [] and a.feed(rec("SYSCALL", 2, comm="x"), 100.0) == []
    assert a.flush(100.05) == []
    assert [e.serial for e in a.flush(100.2)] == [1]
    assert a.flush(101) == [] and a.feed(rec("EOE", 9), 0) == []


def test_selinux_err():
    r = rec("SELINUX_ERR", 3, op="security_compute_av", scontext="a:b:c_t:s0", pid="(null)")
    ev = AvcAssembler()._build([r])[0]
    assert ev.perms == ("security_compute_av",) and ev.pid is None


def test_real_netlink_fixture():
    a = AvcAssembler()
    events = []
    for line in (FIX / "avc_netlink.b64").read_text().split():
        for mtype, text in parse_netlink(base64.b64decode(line)):
            names = {1300: "SYSCALL", 1320: "EOE", 1327: "PROCTITLE", 1400: "AVC"}
            if mtype in names and (r := parse_audit_text(names[mtype], text)):
                events += a.feed(r, 0)
    assert len(events) == 1
    ev = events[0]
    assert (ev.serial, ev.scontext_type, ev.perms) == (918, "httpd_t", ("entrypoint",))
    assert ev.exe == "/usr/lib/systemd/systemd-executor" and ev.comm == "(cat)"


def test_real_log_fixture(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")

    async def go():
        src = LogTailSource(log, interval=0.01)
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write((FIX / "avc_auditlog.txt").read_text())
        out = [await asyncio.wait_for(task, 2)]
        out += [await asyncio.wait_for(anext(it), 2) for _ in range(2)]
        await it.aclose()
        return out

    out = asyncio.run(go())
    assert [r.type for r in out] == ["AVC", "SYSCALL", "PROCTITLE"]
    ev = AvcAssembler()._build(out)  # no EOE in the log: assembled on flush in practice
    assert ev[0].exe == "/usr/lib/systemd/systemd-executor"


def test_logtail_rotation_partial_and_noise(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("type=AVC msg=audit(1.0:1): old\n")

    async def go():
        it = LogTailSource(log, interval=0.01).records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write("type=DAEMON_START msg=audit(1.0:2): x\ntype=EOE msg=audit(1.0:5): ")
        await asyncio.sleep(0.05)  # partial last line must stay buffered
        with log.open("a") as f:
            f.write("\n")
        first = await asyncio.wait_for(task, 2)
        log.rename(tmp_path / "audit.log.1")
        log.write_text("type=EOE msg=audit(2.0:6): \n")
        second = await asyncio.wait_for(anext(it), 2)
        await it.aclose()
        return first, second

    first, second = asyncio.run(go())
    assert first.serial == 5 and second.serial == 6


def test_logtail_truncation_and_late_file(tmp_path):
    log = tmp_path / "audit.log"

    async def go():
        it = LogTailSource(log, interval=0.01).records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        log.write_text("type=EOE msg=audit(1.0:1): padding padding padding\n")
        first = await asyncio.wait_for(task, 2)
        log.write_text("type=EOE msg=audit(1.0:2): \n")  # same inode, shorter
        second = await asyncio.wait_for(anext(it), 2)
        await it.aclose()
        return first, second

    first, second = asyncio.run(go())
    assert (first.serial, second.serial) == (1, 2)


def test_factory_falls_back_to_logfile():
    def deny():
        raise PermissionError("no CAP_AUDIT_READ")

    src = open_source(netlink=deny)
    assert src.name == "logfile"
    q = EventQueue()
    c = AuditCollector(q, CgroupFS(), lambda: src)
    c._source = src
    assert c.health() == {"source": "logfile", "user_avc_truncated": 0}
    assert AuditCollector(q, CgroupFS()).health() == {"source": None, "user_avc_truncated": 0}


@pytest.mark.skipif(sys.platform == "linux", reason="needs a host without AF_NETLINK")
def test_netlink_unavailable_off_linux():
    with pytest.raises(OSError):
        NetlinkSource()


def test_netlink_source_reads_datagrams(monkeypatch):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.setblocking(False)

    class Fake(NetlinkSource):
        def __init__(self) -> None:
            self._sock = a

    async def go():
        it = Fake().records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.01)
        b.send(nl(1000, "audit(1.0:1): skipped") + nl(1320, "audit(5.0:7): "))
        r = await asyncio.wait_for(task, 2)
        await it.aclose()
        return r

    assert asyncio.run(go()).serial == 7
    b.close()


class Stub:
    name = "stub"

    def __init__(self, recs):
        self.recs = recs

    def close(self):
        pass

    async def records(self):
        for r in self.recs:
            yield r
        await asyncio.sleep(0.2)


def test_collector_fills_cgroup_and_flushes(tmp_path):
    proc = tmp_path / "proc"
    (proc / "7").mkdir(parents=True)
    (proc / "7" / "cgroup").write_text("0::/system.slice/httpd.service\n")
    q = EventQueue()
    now = [1_000_000_000]
    recs = [avc(1), avc(2, pid="999"), rec("EOE", 1)]
    c = AuditCollector(q, CgroupFS(tmp_path, proc), lambda: Stub(recs), lambda: now[0], 0.01)

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        now[0] += 200_000  # 0.2 s later: serial 2 times out
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(go())
    evs = [q._q.popleft(), q._q.popleft()]
    assert all(isinstance(e, AvcEvent) for e in evs)
    assert (evs[0].cgroup_at_receipt, evs[0].unit_at_receipt) == (
        "system.slice/httpd.service",
        "httpd.service",
    )
    assert evs[1].cgroup_at_receipt is None and evs[1].unit_at_receipt is None
    assert c.health() == {"source": "stub", "user_avc_truncated": 0}


def test_collector_survives_bad_record(tmp_path):
    q = EventQueue()
    calls = []

    class Flaky(AuditCollector):
        def _publish(self, events):
            if events:
                calls.append(events)
            if len(calls) == 1 and events:
                raise RuntimeError("x")
            super()._publish(events)

    recs = [avc(1), rec("EOE", 1), avc(2), rec("EOE", 2)]
    c = Flaky(q, CgroupFS(tmp_path, tmp_path), lambda: Stub(recs), flush_interval=0.01)

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        t.cancel()

    asyncio.run(go())
    assert [e.serial for e in q._q] == [2]


def test_forged_msg_inside_quoted_value_is_ignored():
    text = (
        'audit(1.0:1): avc:  denied  { read } for  pid=7 comm="x" '
        "name=\"a msg='scontext=system_u:system_r:sshd_t:s0'\" "
        "scontext=a:b:httpd_t:s0 tcontext=a:b:x_t:s0 tclass=file permissive=0"
    )
    r = parse_audit_text("AVC", text)
    ev = AvcAssembler()._build([r])[0]
    assert (ev.scontext_type, ev.perms, ev.tclass, ev.tcontext) == (
        "httpd_t",
        ("read",),
        "file",
        "a:b:x_t:s0",
    )


def test_user_avc_prefers_spid_and_node_prefix_and_known_fallback():
    r = parse_audit_text(
        "USER_AVC",
        "audit(1.0:1): pid=900 msg='avc:  denied  { send_msg } for msgtype=method_call "
        "spid=55 tpid=56 scontext=a:b:c_t:s0 tcontext=a:b:d_t:s0 tclass=dbus permissive=0'",
    )
    assert AvcAssembler()._build([r])[0].pid == 55
    # SYSCALL comm "(null)" falls back to the AVC's own
    sc = rec("SYSCALL", 4, comm="(null)", exe="(null)")
    ev = AvcAssembler()._build([avc(4, comm="real", exe="/bin/real"), sc])[0]
    assert (ev.comm, ev.exe) == ("real", "/bin/real")
    line = LogTailSource._parse("node=host1 type=EOE msg=audit(1.0:9): ")
    assert line is not None and line.serial == 9


def test_logtail_rotation_final_read_and_oversize(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")

    async def go():
        src = LogTailSource(log, interval=0.01)
        src.max_partial = 50
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write("x" * 80)  # oversize partial line is dropped
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write("\ntype=EOE msg=audit(1.0:1): \n")
        first = await asyncio.wait_for(task, 2)
        # last record written to the old file in the same breath as the rotation
        with log.open("a") as f:
            f.write("type=EOE msg=audit(1.0:2): \n")
        log.rename(tmp_path / "old")
        log.write_text("type=EOE msg=audit(1.0:3): \n")
        got = [await asyncio.wait_for(anext(it), 2) for _ in range(2)]
        await it.aclose()
        return first, got

    first, got = asyncio.run(go())
    assert first.serial == 1 and [r.serial for r in got] == [2, 3]


def test_logtail_unreadable_is_reported_not_fatal(tmp_path):
    log = tmp_path / "audit.log"
    src = LogTailSource(log, interval=0.01)
    c = AuditCollector(EventQueue(), CgroupFS(), lambda: src)

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        missing = c.health()
        log.write_text("")
        await asyncio.sleep(0.05)
        t.cancel()
        return missing

    missing = asyncio.run(go())
    assert missing["source"] == "logfile" and "error" in missing
    assert c.health() == {"source": "logfile", "user_avc_truncated": 0}


def test_collector_final_flush_and_closes_source():
    closed = []

    class Src(Stub):
        def close(self):
            closed.append(1)

        async def records(self):
            yield avc(1)

    q = EventQueue()
    c = AuditCollector(q, CgroupFS(), lambda: Src([]), flush_interval=10)
    asyncio.run(c.run())
    assert len(q) == 1 and closed


def test_netlink_close_without_iterating():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

    class Fake(NetlinkSource):
        def __init__(self) -> None:
            self._sock = a
            self._loop = None

    Fake().close()
    assert a.fileno() == -1
    b.close()


def test_netlink_storm_bounded_and_fatal_error_ends_source():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.setblocking(False)

    class Fake(NetlinkSource):
        max_batch = 4
        max_queued = 3

        def __init__(self) -> None:
            self._sock = a
            self._loop = None
            self.dropped = 0

    async def go():
        src = Fake()
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.01)
        for n in range(10):
            b.send(nl(1320, f"audit(1.0:{n}): "))
        await asyncio.wait_for(task, 2)
        await asyncio.sleep(0.05)
        drained = []
        for _ in range(3):
            drained.append((await asyncio.wait_for(anext(it), 2)).serial)
        b.close()
        a.close()  # closing the sockets must not break teardown
        return src, drained

    src, drained = asyncio.run(go())
    assert src.dropped > 0 and drained == sorted(drained)


def test_netlink_fatal_recv_error_raises():
    class Boom:
        def fileno(self):
            return 99

        def recv(self, n):
            raise OSError(errno.EIO, "boom")

        def close(self):
            pass

    class Fake(NetlinkSource):
        def __init__(self) -> None:
            self._sock = Boom()
            self._loop = None
            self.dropped = 0

    async def go():
        loop = asyncio.get_running_loop()
        removed = []
        loop.add_reader = lambda fd, cb: cb()  # fire immediately
        loop.remove_reader = lambda fd: removed.append(fd)
        with pytest.raises(OSError):
            await anext(Fake().records())
        return removed

    assert 99 in asyncio.run(go())


DBUS = (
    "audit(1.0:30): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 "
    "msg='avc:  denied  { start } for auid=1000 uid=0 gid=0 "
    'path="/usr/lib/systemd/system/x.service" cmdline="%s" function="mac_selinux_filter" '
    "scontext=unconfined_u:unconfined_r:unconfined_t:s0 "
    "tcontext=system_u:object_r:systemd_unit_file_t:s0 tclass=service permissive=0 "
    'exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?\''
)


@pytest.mark.parametrize(
    "cmdline",
    [
        "systemctl start x",
        "x\" scontext=F:F:sshd_t:s0 tclass=forged z='",
        'x" scontext=F:F:sshd_t:s0 tclass=forged z=',
        "x scontext=F:F:sshd_t:s0 tcontext=F:F:F_t:s0 tclass=forged permissive=1 spid=1",
    ],
)
def test_user_avc_caller_text_cannot_forge(cmdline):
    r = parse_audit_text("USER_AVC", DBUS % cmdline)
    ev = AvcAssembler()._build([r])[0]
    assert (ev.scontext_type, ev.tclass, ev.perms, ev.denied) == (
        "unconfined_t",
        "service",
        ("start",),
        True,
    )
    assert ev.tcontext.endswith("systemd_unit_file_t:s0") and not ev.permissive


def test_user_avc_enriched_tail_after_closing_quote_is_ignored():
    r = parse_audit_text("USER_AVC", DBUS % "systemctl" + '\x1dAUID="x" scontext=a:b:evil_t:s0')
    assert r is not None and r.fields["scontext"].endswith("unconfined_t:s0")


def test_logtail_unreadable_at_start_does_not_replay(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("type=EOE msg=audit(1.0:1): \n")
    log.chmod(0)

    async def go():
        it = LogTailSource(log, interval=0.01).records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        log.chmod(0o644)
        await asyncio.sleep(0.05)  # let the tail reopen (at EOF) before appending
        with log.open("a") as f:
            f.write("type=EOE msg=audit(1.0:2): \n")
        r = await asyncio.wait_for(task, 2)
        await it.aclose()
        return r

    import os

    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    assert asyncio.run(go()).serial == 2


def test_logtail_oversize_line_skipped_to_newline_and_read_error(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")

    async def go():
        src = LogTailSource(log, interval=0.01)
        src.max_partial = 20
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        with log.open("a") as f:
            f.write("y" * 30)
        await asyncio.sleep(0.05)
        with log.open("a") as f:  # the tail of the oversized line looks like a record
            f.write(" type=EOE msg=audit(1.0:8): \ntype=EOE msg=audit(1.0:9): \n")
        r = await asyncio.wait_for(task, 2)
        await it.aclose()
        return r

    assert asyncio.run(go()).serial == 9


def test_logtail_read_error_is_reported(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    log.write_text("")
    src = LogTailSource(log, interval=0.01)
    real = Path.open
    state = {"n": 0}

    class Bad:
        def __init__(self, f):
            self._f = f

        def read(self):
            state["n"] += 1
            if state["n"] == 1:
                raise OSError(errno.EIO, "io")
            return self._f.read()

        def __getattr__(self, k):
            return getattr(self._f, k)

    def fake_open(self, mode="r", *a, **k):
        f = real(self, mode, *a, **k)
        return Bad(f) if mode == "rb" else f

    monkeypatch.setattr(Path, "open", fake_open)

    async def go():
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.1)
        with log.open("a") as f:
            f.write("type=EOE msg=audit(1.0:4): \n")
        r = await asyncio.wait_for(task, 2)
        await it.aclose()
        return r

    assert asyncio.run(go()).serial == 4


def test_user_avc_dbus_record_gives_spid_and_no_comm():
    r = parse_audit_text(
        "USER_AVC",
        "audit(1.0:31): pid=700 uid=81 auid=4294967295 ses=4294967295 subj=system_u:system_r:"
        "system_dbusd_t:s0 msg='avc:  denied  { send_msg } for msgtype=method_call "
        "interface=org.freedesktop.systemd1.Manager member=StartUnit dest=org.freedesktop.systemd1 "
        "spid=4242 tpid=1 scontext=system_u:system_r:httpd_t:s0 "
        "tcontext=system_u:system_r:init_t:s0 tclass=dbus permissive=0 "
        'exe="/usr/bin/dbus-daemon" sauid=81 hostname=? addr=? terminal=?\'',
    )
    ev = AvcAssembler()._build([r, rec("SYSCALL", 31, comm="sc", exe="/sc")])[0]
    assert (ev.pid, ev.comm, ev.exe, ev.scontext_type) == (4242, None, None, "httpd_t")
    assert "comm" not in ev.raw and "spid=4242" in ev.raw


def test_user_avc_systemd_record_has_no_trusted_pid():
    ev = AvcAssembler()._build(
        [parse_audit_text("USER_AVC", DBUS % 'x spid=4242 pid=777 comm="sshd" exe="/e')]
    )[0]
    assert ev.pid is None and ev.comm is None and "4242" not in ev.raw and "777" not in ev.raw


@pytest.mark.parametrize("filler", ["A", "\u00e9", "\U0001f600"])
def test_truncated_user_avc_is_dropped_and_counted(filler):
    # libselinux cuts at 1024 bytes, not characters: multibyte cmdline filler
    # must not slip a forged triple and spid past the guard.
    head = 'avc:  denied  { start } for auid=1000 uid=0 gid=0 cmdline="'
    forged = " spid=1 scontext=F:F:sshd_t:s0 tcontext=F:F:F_t:s0 tclass=forged permissive=0"
    n = (1023 - len((head + forged).encode())) // len(filler.encode())
    selinux = (head + filler * n + forged).encode()[:1023].decode()
    assert len(selinux) < 1000 or filler == "A"
    body = (
        "audit(1.0:32): pid=1 uid=0 auid=4294967295 ses=4294967295 "
        "subj=system_u:system_r:init_t:s0 msg='"
        + selinux
        + ' exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?\''
    )
    q = EventQueue()
    recs = [parse_audit_text("USER_AVC", body), rec("EOE", 32)]
    c = AuditCollector(q, CgroupFS(), lambda: Stub(recs), flush_interval=0.01)

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        t.cancel()

    asyncio.run(go())
    assert not q._q and c.health()["user_avc_truncated"] == 1


def test_logtail_persistent_read_error_does_not_spin(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    log.write_text("")
    src = LogTailSource(log, interval=0.02)
    held = Path.open(log, "rb")  # one real fd for os.fstat, closed below

    class Bad:
        def read(self):
            raise OSError(errno.EIO, "io")

        def tell(self):
            return 0

        def seek(self, *a):
            pass

        def fileno(self):
            return held.fileno()

        def close(self):
            pass

    monkeypatch.setattr(Path, "open", lambda self, mode="r", *a, **k: Bad())
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.001)

    async def go():
        t = asyncio.ensure_future(ticker())
        it = src.records()
        reader = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.2)
        reader.cancel()
        t.cancel()

    asyncio.run(go())
    held.close()
    assert ticks > 20 and src.error is not None


def test_netlink_overruns_counted_and_reported_as_audit_drops():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.setblocking(False)

    class Overrun:
        calls = 0

        def fileno(self):
            return a.fileno()

        def recv(self, n):
            self.calls += 1
            if self.calls <= 2:
                raise OSError(errno.ENOBUFS, "No buffer space available")
            return a.recv(n)

        def getsockopt(self, *args):
            return 425984

        def close(self):
            a.close()

    class Fake(NetlinkSource):
        def __init__(self) -> None:
            self._sock = Overrun()
            self._loop = None

    q = EventQueue()
    c = AuditCollector(q, CgroupFS(), Fake, flush_interval=0.01)

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.02)
        b.send(nl(1320, "audit(1.0:1): "))
        await asyncio.sleep(0.05)
        health = c.health()
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        return health

    health = asyncio.run(go())
    b.close()
    assert health["overruns"] == 2 and health["rcvbuf"] == 425984
    assert q.dropped["audit"] == 2


def test_netlink_asks_for_a_bigger_receive_buffer(monkeypatch):
    calls = []

    class Sock:
        def __init__(self, *a):
            pass

        def setblocking(self, flag):
            pass

        def setsockopt(self, level, opt, value):
            calls.append((level, opt, value))

        def bind(self, addr):
            pass

    monkeypatch.setattr(socket, "AF_NETLINK", 16, raising=False)
    monkeypatch.setattr(socket, "socket", Sock)
    NetlinkSource()
    assert calls == [(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)]


def test_collector_records_when_its_source_has_caught_up(tmp_path):
    class Drained(Stub):
        def caught_up(self):
            return 4.0

    q = EventQueue()
    c = AuditCollector(
        q, CgroupFS(tmp_path, tmp_path), lambda: Drained([avc(1), rec("EOE", 1)]),
        lambda: 5_000_000, 0.01,
    )  # fmt: skip

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    assert c.caught_up_us is None
    asyncio.run(go())
    assert c.caught_up_us == 4_000_000


def test_collector_stays_behind_a_record_group_still_open(tmp_path):
    class Drained(Stub):
        def caught_up(self):
            return 4.0

    q = EventQueue()
    # no EOE and the clock stands still, so serial 1 stays open in the assembler
    c = AuditCollector(
        q, CgroupFS(tmp_path, tmp_path), lambda: Drained([avc(1)]), lambda: 5_000_000, 0.01
    )

    async def go():
        t = asyncio.ensure_future(c.run())
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(go())
    assert c.caught_up_us == avc(1).ts_us - 1  # its event isn't published yet


def test_logtail_caught_up_only_while_idle_at_eof(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("")

    async def go():
        src = LogTailSource(log, interval=0.01)
        assert src.caught_up() is None
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.05)
        idle = src.caught_up()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await it.aclose()
        return idle

    idle = asyncio.run(go())
    assert idle is not None and abs(idle - time.time()) < 5


def test_netlink_watermark_follows_audit_stamps_not_the_socket():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    a.setblocking(False)

    class Fake(NetlinkSource):
        quiet_after = 0.05

        def __init__(self) -> None:
            self._sock = a

    async def go():
        src = Fake()
        it = src.records()
        task = asyncio.ensure_future(anext(it))
        await asyncio.sleep(0.01)
        # a record type we don't parse still proves everything older was read
        b.send(nl(1320, "audit(9.500:2): ") + nl(1000, "audit(9.700:3): skipped"))
        await asyncio.wait_for(task, 2)
        busy = src.caught_up()  # the kernel may still be behind: trust the stamps
        await asyncio.sleep(0.1)
        quiet = src.caught_up()  # nothing for a while and nothing waiting
        await it.aclose()
        return busy, quiet

    busy, quiet = asyncio.run(go())
    b.close()
    assert busy == 9.7
    assert quiet is not None and abs(quiet - time.time()) < 5
