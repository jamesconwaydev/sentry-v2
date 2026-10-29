"""Audit collector: SELinux AVC denials from the kernel audit netlink socket.

Falls back to tailing audit.log when the daemon lacks CAP_AUDIT_READ.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import errno
import logging
import os
import re
import select
import socket
import struct
import time
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..cgroupfs import CgroupFS
from ..events import AvcEvent, EventQueue

log = logging.getLogger(__name__)

NETLINK_AUDIT = 9
AUDIT_NLGRP_READLOG = 1
RECV_SIZE = 65536  # MAX_AUDIT_MESSAGE_LENGTH is 8970
RCVBUF = 8 << 20  # asked for; the kernel caps it at net.core.rmem_max
NETLINK_TYPES = {
    1300: "SYSCALL",
    1320: "EOE",
    1327: "PROCTITLE",
    1400: "AVC",
    1401: "SELINUX_ERR",
    1107: "USER_AVC",
}
AVC_TYPES = frozenset({"AVC", "USER_AVC", "SELINUX_ERR"})

_STAMP = re.compile(r"audit\((\d+)\.(\d+):(\d+)\):\s?(.*)", re.S)
_CONTEXTS = re.compile(r"scontext=(\S+) tcontext=(\S+) tclass=(\S+)")
# libaudit's own trailing fields, appended after the libselinux text
_AUDIT_TAIL = re.compile(
    r""" exe="[^"]*"(?: sauid=\S+)?(?: hostname=\S+)?(?: addr=\S+)?(?: terminal=\S+)?\s*$"""
)
TRUNCATION_LIMIT = 1000  # libselinux formats into a 1024-byte buffer
_PAIR = re.compile(r"""(\w+)=("[^"]*"|'[^']*'|\S+)""")
_VERDICT = re.compile(r"avc:\s+(denied|granted)\s+\{([^}]*)\}")
_LOG_LINE = re.compile(r"(?:node=\S+ )?type=(\w+) msg=(audit\(.*)", re.S)
_HEX_KEYS = ("comm", "exe", "proctitle", "path", "name")


@dataclass(frozen=True)
class AuditRecord:
    type: str
    ts_us: int
    serial: int
    fields: dict[str, str]


def _decode(key: str, value: str) -> str:
    """Quoted values lose their quotes; unquoted even-length hex is decoded."""
    if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2:
        return value[1:-1]
    if key in _HEX_KEYS and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        raw = bytes.fromhex(value).replace(b"\0", b" ").decode("utf-8", "replace")
        return raw.strip()
    return value


def _pairs(text: str) -> dict[str, str]:
    return {k: _decode(k, v) for k, v in _PAIR.findall(text)}


def parse_audit_text(type_name: str, text: str) -> AuditRecord | None:
    """Parse the text from `audit(sec.ms:serial): ...` onward."""
    m = _STAMP.match(text if type_name == "USER_AVC" else text.split("\x1d", 1)[0])
    if m is None:
        return None
    sec, ms, serial, body = m.groups()
    fields: dict[str, str] = {}
    if type_name == "USER_AVC":
        fields.update(_user_avc_fields(body))
    else:
        if v := _VERDICT.match(body):
            fields["verdict"] = v.group(1)
            fields["perms"] = " ".join(v.group(2).split())
        fields.update(_pairs(body))
    return AuditRecord(
        type_name, int(sec) * 1_000_000 + int(ms.ljust(3, "0")[:3]) * 1000, int(serial), fields
    )


def _user_avc_fields(body: str) -> dict[str, str]:
    """The trusted fields of a USER_AVC, whose msg='...' embeds caller text.

    systemd puts cmdline="..." in there, so quoting cannot be trusted. The
    nested record runs to the last quote; userspace object managers append
    scontext/tcontext/tclass after the caller text, so the last match wins.
    Only fields from that tail are returned, and a record whose tail may have
    been cut off by the 1024-byte libselinux buffer is marked "truncated".
    """
    start = body.find("msg='")
    end = body.rfind("'")  # anything after the closing quote is enriched data
    if start < 0 or end <= start + 5:
        return {}
    inner = body[start + 5 : end]
    tail = _AUDIT_TAIL.search(inner)
    if len(inner[: tail.start() if tail else len(inner)].encode()) >= TRUNCATION_LIMIT:
        return {"truncated": "1"}
    fields: dict[str, str] = {}
    if v := _VERDICT.match(inner):
        fields["verdict"] = v.group(1)
        fields["perms"] = " ".join(v.group(2).split())
    if ctx := list(_CONTEXTS.finditer(inner)):
        last = ctx[-1]
        fields["scontext"], fields["tcontext"], fields["tclass"] = last.groups()
        if p := re.search(r"\bpermissive=([01])\b", inner[last.end() :]):
            fields["permissive"] = p.group(1)
        # dbus-daemon's unquoted aux fields (spid=) sit between the last quote
        # and the contexts; systemd's segment is empty, so it has no trusted pid.
        segment = inner[inner.rfind('"', 0, last.start()) + 1 : last.start()]
        for k in ("pid", "spid"):
            if hits := re.findall(rf"\b{k}=(\d+)", segment):
                fields[k] = hits[-1]
    return fields


def parse_netlink(buf: bytes) -> list[tuple[int, str]]:
    """Split a recv() buffer into (nlmsg_type, payload text) pairs."""
    out: list[tuple[int, str]] = []
    off = 0
    while off + 16 <= len(buf):
        length, mtype, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, off)
        if length < 16 or off + length > len(buf):
            break
        payload = buf[off + 16 : off + length].rstrip(b"\0")
        out.append((mtype, payload.decode("utf-8", "replace")))
        off += (length + 3) & ~3
    return out


class AvcAssembler:
    """Groups records by serial and emits one AvcEvent per AVC record."""

    def __init__(self, flush_after: float = 0.1) -> None:
        self.truncated = 0
        self._warned_at = float("-inf")
        self._flush_after = flush_after
        self._groups: dict[int, tuple[float, list[AuditRecord]]] = {}

    def feed(self, rec: AuditRecord, now: float) -> list[AvcEvent]:
        if rec.type == "EOE":
            group = self._groups.pop(rec.serial, None)
            return self._build(group[1]) if group else []
        self._groups.setdefault(rec.serial, (now, []))[1].append(rec)
        return []

    def oldest_pending_us(self) -> int | None:
        """Audit time of the oldest record group still waiting for the rest."""
        return min((recs[0].ts_us for _t, recs in self._groups.values()), default=None)

    def flush(self, now: float) -> list[AvcEvent]:
        due = [s for s, (t, _) in self._groups.items() if now - t >= self._flush_after]
        return [ev for s in due for ev in self._build(self._groups.pop(s)[1])]

    def _build(self, group: list[AuditRecord]) -> list[AvcEvent]:
        syscall = next((r.fields for r in group if r.type == "SYSCALL"), {})
        events = []
        for r in group:
            if r.type not in AVC_TYPES:
                continue
            f = r.fields
            if f.get("truncated"):
                self.truncated += 1
                if time.monotonic() - self._warned_at >= 60:
                    self._warned_at = time.monotonic()
                    log.warning(
                        "dropped USER_AVC that may be truncated (%d so far)", self.truncated
                    )
                continue
            user = r.type == "USER_AVC"  # caller-chosen comm/exe are not attribution
            pid = (f.get("spid") if user else None) or f.get("pid", "")
            ppid = "" if user else syscall.get("ppid", "")
            scontext = f.get("scontext", "")
            parts = scontext.split(":")
            perms = tuple(f["perms"].split()) if "perms" in f else ((f["op"],) if "op" in f else ())
            events.append(
                AvcEvent(
                    ts_us=r.ts_us,
                    serial=r.serial,
                    denied=f.get("verdict", "denied") == "denied",
                    perms=perms,
                    scontext=scontext,
                    scontext_type=parts[2] if len(parts) > 2 else "",
                    tcontext=f.get("tcontext", ""),
                    tclass=f.get("tclass", ""),
                    comm=None if user else _known(syscall.get("comm")) or _known(f.get("comm")),
                    exe=None if user else _known(syscall.get("exe")) or _known(f.get("exe")),
                    pid=int(pid) if pid.isascii() and pid.isdigit() else None,
                    ppid=int(ppid) if ppid.isascii() and ppid.isdigit() else None,
                    permissive=f.get("permissive") == "1",
                    raw=" ".join(f"{k}={v}" for k, v in f.items()),
                )
            )
        return events


def _known(value: str | None) -> str | None:
    return None if value in (None, "", "(null)") else value


class Source(Protocol):
    name: str

    def records(self) -> AsyncGenerator[AuditRecord, None]: ...

    def caught_up(self) -> float | None:
        """Wall time up to which every record has been yielded, if it is now."""
        ...

    def close(self) -> None: ...


class NetlinkSource:
    name = "netlink"
    max_batch = 64  # recvs per loop callback, so an audit storm cannot starve the loop
    max_queued = 10_000
    dropped = 0  # records shed because the queue below was full
    overruns = 0  # ENOBUFS: the kernel dropped records before we read them
    quiet_after = 1.0  # seconds without a message before "caught up" means now
    _q: asyncio.Queue[AuditRecord | OSError] | None = None
    _seen_us = 0  # newest audit stamp read off the socket, of any record type
    _yielded_us = 0  # newest stamp handed on
    _last_msg = float("-inf")  # monotonic time of the last message read

    def __init__(self) -> None:
        af = getattr(socket, "AF_NETLINK", None)
        if af is None:
            raise OSError("AF_NETLINK is not available on this platform")
        self._sock = socket.socket(af, socket.SOCK_RAW, NETLINK_AUDIT)
        self._loop: asyncio.AbstractEventLoop | None = None
        try:
            self._sock.setblocking(False)
            with contextlib.suppress(OSError):
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
            self._sock.bind((0, AUDIT_NLGRP_READLOG))  # needs CAP_AUDIT_READ
        except OSError:
            self._sock.close()
            raise

    def caught_up(self) -> float | None:
        """The audit time up to which every record has been handed on.

        The kernel sends records in order, but in a denial storm its own
        queue can run seconds behind, so an empty socket proves nothing.
        The newest stamp read does: everything older has been read. Only
        after a quiet second with nothing waiting is it simply now.
        """
        if self._q is None:
            return None
        if not self._q.empty():
            return self._yielded_us / 1_000_000 if self._yielded_us else None
        if time.monotonic() - self._last_msg >= self.quiet_after:
            try:
                if not select.select([self._sock], [], [], 0)[0]:
                    return time.time()
            except (OSError, ValueError):
                pass
        return self._seen_us / 1_000_000 if self._seen_us else None

    @property
    def rcvbuf(self) -> int:
        """The receive buffer the kernel granted, in bytes."""
        return self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)

    def close(self) -> None:
        if self._loop is not None:
            with contextlib.suppress(ValueError, RuntimeError):
                self._loop.remove_reader(self._sock.fileno())
            self._loop = None
        self._sock.close()

    async def records(self) -> AsyncGenerator[AuditRecord, None]:
        loop = self._loop = asyncio.get_running_loop()
        q: asyncio.Queue[AuditRecord | OSError] = asyncio.Queue(self.max_queued)
        self._q = q

        def push(item: AuditRecord | OSError) -> None:
            if q.full():
                q.get_nowait()
                self.dropped += 1
                if self.dropped == 1 or self.dropped % 1000 == 0:
                    log.warning("audit queue full; dropped %d records", self.dropped)
            q.put_nowait(item)

        def on_readable() -> None:
            for _ in range(self.max_batch):
                try:
                    buf = self._sock.recv(RECV_SIZE)
                except BlockingIOError:
                    return
                except OSError as e:
                    if e.errno == errno.ENOBUFS:  # the kernel dropped messages
                        self.overruns += 1
                        if self.overruns == 1 or self.overruns % 1000 == 0:
                            log.warning("audit netlink overrun (%d so far): %s", self.overruns, e)
                        continue
                    loop.remove_reader(self._sock.fileno())
                    push(e)
                    return
                self._last_msg = time.monotonic()
                for mtype, text in parse_netlink(buf):
                    if m := _STAMP.match(text):
                        self._seen_us = max(self._seen_us, int(m[1]) * 1_000_000 + int(m[2]) * 1000)
                    if (name := NETLINK_TYPES.get(mtype)) and (rec := parse_audit_text(name, text)):
                        push(rec)

        loop.add_reader(self._sock.fileno(), on_readable)
        try:
            while True:
                item = await q.get()
                if isinstance(item, OSError):
                    raise item
                self._yielded_us = max(self._yielded_us, item.ts_us)
                yield item
        finally:
            self.close()


class LogTailSource:
    name = "logfile"
    max_partial = 1 << 20

    def __init__(self, path: Path = Path("/var/log/audit/audit.log"), interval: float = 0.25):
        self._path = path
        self._interval = interval
        self.error: str | None = None
        self._read_to_eof_at: float | None = None  # set while idle after a full read
        self._yielded_us = 0

    def close(self) -> None:
        pass  # the file handle is released when records() is closed

    def caught_up(self) -> float | None:
        """When the file was last read to its end, or else the newest stamp handed on."""
        if self._read_to_eof_at is not None:
            return self._read_to_eof_at
        return self._yielded_us / 1_000_000 if self._yielded_us else None

    def _fail(self, e: OSError) -> None:
        if self.error is None:
            log.warning("audit log %s unreadable: %s", self._path, e)
        self.error = str(e)

    async def records(self) -> AsyncGenerator[AuditRecord, None]:
        fh: Any = None
        ino = None
        buf = b""
        discarding = False  # inside an oversized line, skipping to its newline
        start_ino: int | None = None
        started = False
        try:
            while True:
                try:
                    st: os.stat_result | None = self._path.stat()
                except OSError as e:
                    st = None
                    self._fail(e)
                if not started:
                    # Only the file present at startup is skipped to EOF; one
                    # that appears later is read from its first byte.
                    started, start_ino = True, st.st_ino if st else None
                # stat before the final read: whatever the old file held when we
                # noticed the rotation is consumed before we switch.
                rotated = st is not None and (
                    fh is None or st.st_ino != ino or st.st_size < fh.tell()
                )
                if fh is not None:
                    try:
                        data = fh.read()
                    except OSError as e:
                        # Fall through to the poll sleep: a persistent error
                        # must not spin the event loop.
                        # The reopen seeks to EOF, so lines written during the
                        # error window are skipped; replaying them risks duplicates.
                        self._fail(e)
                        fh.close()
                        fh, start_ino = None, st.st_ino if st else None
                    else:
                        self.error = None
                        if discarding:
                            _, nl, data = data.partition(b"\n")
                            discarding = not nl
                        buf += data
                        *lines, buf = buf.split(b"\n")  # last item is a partial line
                        for line in lines:
                            if rec := self._parse(line.decode("utf-8", "replace")):
                                self._yielded_us = max(self._yielded_us, rec.ts_us)
                                yield rec
                        if len(buf) > self.max_partial:
                            log.warning("audit log line over %d bytes; dropped", self.max_partial)
                            buf, discarding = b"", True
                if rotated:
                    if fh is not None:
                        fh.close()
                        fh = None
                    try:
                        fh = self._path.open("rb")
                        ino = os.fstat(fh.fileno()).st_ino
                        if ino == start_ino:
                            fh.seek(0, os.SEEK_END)
                        start_ino = None
                        buf, discarding = b"", False
                        continue
                    except OSError as e:
                        if fh is not None:
                            fh.close()
                            fh = None
                        self._fail(e)
                if self.error is None and not buf:
                    self._read_to_eof_at = time.time()
                await asyncio.sleep(self._interval)
                self._read_to_eof_at = None
        finally:
            if fh is not None:
                fh.close()

    @staticmethod
    def _parse(line: str) -> AuditRecord | None:
        m = _LOG_LINE.match(line)
        if m is None or m.group(1) not in NETLINK_TYPES.values():
            return None
        return parse_audit_text(m.group(1), m.group(2))


def open_source(
    netlink: Callable[[], Source] = NetlinkSource,
    logfile: Callable[[], Source] = LogTailSource,
) -> Source:
    """Prefer netlink; fall back to the log file without CAP_AUDIT_READ."""
    try:
        return netlink()
    except OSError as e:
        log.warning("audit netlink unavailable (%s); tailing the audit log instead", e)
        return logfile()


class AuditCollector:
    def __init__(
        self,
        queue: EventQueue,
        fs: CgroupFS,
        source_factory: Callable[[], Source] = open_source,
        clock: Callable[[], int] = lambda: time.time_ns() // 1000,
        flush_interval: float = 0.05,
    ) -> None:
        self._queue = queue
        self._fs = fs
        self._factory = source_factory
        self._clock = clock
        self._flush_interval = flush_interval
        self._asm = AvcAssembler()
        self._source: Source | None = None
        self._lost = 0
        # audit time (µs) up to which every record has been published to the queue
        self.caught_up_us: int | None = None

    def health(self) -> dict[str, object]:
        out: dict[str, object] = {
            "source": self._source.name if self._source else None,
            "user_avc_truncated": self._asm.truncated,
        }
        if error := getattr(self._source, "error", None):
            out["error"] = error
        if isinstance(self._source, NetlinkSource):
            out["overruns"] = self._source.overruns
            with contextlib.suppress(OSError):
                out["rcvbuf"] = self._source.rcvbuf
        return out

    def _count_lost(self) -> None:
        """Add records the source lost to the queue's audit drop count."""
        s = self._source
        n = getattr(s, "dropped", 0) + getattr(s, "overruns", 0)
        if n > self._lost:
            self._queue.dropped["audit"] += n - self._lost
            self._lost = n

    def _publish(self, events: list[AvcEvent]) -> None:
        for ev in events:
            cgroup = self._fs.pid_cgroup(ev.pid) if ev.pid is not None else None
            unit = self._fs.unit_of(cgroup) if cgroup else None
            parent = None
            # gone already; its parent may not be. PID 1 is every main process's parent.
            if cgroup is None and ev.ppid is not None and ev.ppid > 1:
                parent = self._fs.pid_cgroup(ev.ppid)
            self._queue.put_nowait(
                dataclasses.replace(
                    ev,
                    cgroup_at_receipt=cgroup,
                    unit_at_receipt=unit,
                    parent_cgroup_at_receipt=parent,
                    parent_unit_at_receipt=self._fs.unit_of(parent) if parent else None,
                )
            )

    def _now(self) -> float:
        return self._clock() / 1_000_000

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            try:
                self._publish(self._asm.flush(self._now()))
                self._count_lost()
                self._note_caught_up()
            except Exception:
                log.exception("audit flush failed")

    def _note_caught_up(self) -> None:
        caught_up = getattr(self._source, "caught_up", None)
        if caught_up is None or (t := caught_up()) is None:
            return
        us = int(t * 1_000_000)
        if (oldest := self._asm.oldest_pending_us()) is not None:
            us = min(us, oldest - 1)  # that group's events aren't published yet
        self.caught_up_us = us

    async def run(self) -> None:
        self._source = source = self._factory()
        # The log file is polled, so a group may legitimately wait a full poll.
        self._asm = AvcAssembler(0.5 if source.name == "logfile" else 0.1)
        flusher = asyncio.create_task(self._flusher())
        try:
            async with contextlib.aclosing(source.records()) as records:
                async for rec in records:
                    try:
                        self._publish(self._asm.feed(rec, self._now()))
                    except Exception:
                        log.exception("audit record handling failed")
        finally:
            flusher.cancel()
            source.close()
            self._count_lost()
            try:
                self._publish(self._asm.flush(float("inf")))
            except Exception:
                log.exception("audit final flush failed")
