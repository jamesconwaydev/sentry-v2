"""Audit collector: SELinux AVC denials from the kernel audit netlink socket.

Falls back to tailing audit.log when the daemon lacks CAP_AUDIT_READ.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import re
import socket
import struct
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..cgroupfs import CgroupFS
from ..events import AvcEvent, EventQueue

log = logging.getLogger(__name__)

NETLINK_AUDIT = 9
AUDIT_NLGRP_READLOG = 1
RECV_SIZE = 65536  # MAX_AUDIT_MESSAGE_LENGTH is 8970
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
_INNER = re.compile(r"\bmsg='(.*)'", re.S)
_PAIR = re.compile(r"""(\w+)=("[^"]*"|'[^']*'|\S+)""")
_VERDICT = re.compile(r"avc:\s+(denied|granted)\s+\{([^}]*)\}")
_LOG_LINE = re.compile(r"type=(\w+) msg=(audit\(.*)", re.S)
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
    text = text.split("\x1d", 1)[0]  # auditd "enriched" fields follow the separator
    m = _STAMP.match(text)
    if m is None:
        return None
    sec, ms, serial, body = m.groups()
    fields: dict[str, str] = {}
    if inner := _INNER.search(body):  # USER_AVC nests the real record in msg='...'
        fields.update(_pairs(body[: inner.start()]))
        body = inner.group(1)
    if v := _VERDICT.search(body):
        fields["verdict"] = v.group(1)
        fields["perms"] = " ".join(v.group(2).split())
    fields.update(_pairs(body))
    return AuditRecord(
        type_name, int(sec) * 1_000_000 + int(ms.ljust(3, "0")[:3]) * 1000, int(serial), fields
    )


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
        self._flush_after = flush_after
        self._groups: dict[int, tuple[float, list[AuditRecord]]] = {}

    def feed(self, rec: AuditRecord, now: float) -> list[AvcEvent]:
        if rec.type == "EOE":
            group = self._groups.pop(rec.serial, None)
            return self._build(group[1]) if group else []
        self._groups.setdefault(rec.serial, (now, []))[1].append(rec)
        return []

    def flush(self, now: float) -> list[AvcEvent]:
        due = [s for s, (t, _) in self._groups.items() if now - t >= self._flush_after]
        return [ev for s in due for ev in self._build(self._groups.pop(s)[1])]

    @staticmethod
    def _build(group: list[AuditRecord]) -> list[AvcEvent]:
        syscall = next((r.fields for r in group if r.type == "SYSCALL"), {})
        events = []
        for r in group:
            if r.type not in AVC_TYPES:
                continue
            f = r.fields
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
                    comm=_known(syscall.get("comm") or f.get("comm")),
                    exe=_known(syscall.get("exe") or f.get("exe")),
                    pid=int(f["pid"]) if f.get("pid", "").isdigit() else None,
                    permissive=f.get("permissive") == "1",
                    raw=" ".join(f"{k}={v}" for k, v in f.items()),
                )
            )
        return events


def _known(value: str | None) -> str | None:
    return None if value in (None, "", "(null)") else value


class Source(Protocol):
    name: str

    def records(self) -> AsyncIterator[AuditRecord]: ...


class NetlinkSource:
    name = "netlink"

    def __init__(self) -> None:
        af = getattr(socket, "AF_NETLINK", None)
        if af is None:
            raise OSError("AF_NETLINK is not available on this platform")
        self._sock = socket.socket(af, socket.SOCK_RAW, NETLINK_AUDIT)
        try:
            self._sock.setblocking(False)
            self._sock.bind((0, AUDIT_NLGRP_READLOG))  # needs CAP_AUDIT_READ
        except OSError:
            self._sock.close()
            raise

    async def records(self) -> AsyncIterator[AuditRecord]:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[AuditRecord] = asyncio.Queue()

        def on_readable() -> None:
            while True:
                try:
                    buf = self._sock.recv(RECV_SIZE)
                except BlockingIOError:
                    return
                except OSError as e:  # ENOBUFS: the kernel dropped messages
                    log.warning("audit netlink recv failed: %s", e)
                    return
                for mtype, text in parse_netlink(buf):
                    if (name := NETLINK_TYPES.get(mtype)) and (rec := parse_audit_text(name, text)):
                        q.put_nowait(rec)

        loop.add_reader(self._sock.fileno(), on_readable)
        try:
            while True:
                yield await q.get()
        finally:
            loop.remove_reader(self._sock.fileno())
            self._sock.close()


class LogTailSource:
    name = "logfile"

    def __init__(self, path: Path = Path("/var/log/audit/audit.log"), interval: float = 0.25):
        self._path = path
        self._interval = interval

    async def records(self) -> AsyncIterator[AuditRecord]:
        fh: Any = None
        ino = None
        buf = b""
        try:
            with contextlib.suppress(OSError):
                fh = self._path.open("rb")
                fh.seek(0, os.SEEK_END)
                ino = os.fstat(fh.fileno()).st_ino
            while True:
                if fh is not None:
                    buf += fh.read()
                    *lines, buf = buf.split(b"\n")  # last item is a partial line
                    for line in lines:
                        if rec := self._parse(line.decode("utf-8", "replace")):
                            yield rec
                try:
                    st = self._path.stat()
                except OSError:
                    st = None
                # The old file was drained above, so it is safe to switch.
                if st and (fh is None or st.st_ino != ino or st.st_size < fh.tell()):
                    if fh is not None:
                        fh.close()
                    fh, ino, buf = self._path.open("rb"), st.st_ino, b""
                    continue
                await asyncio.sleep(self._interval)
        finally:
            if fh is not None:
                fh.close()

    @staticmethod
    def _parse(line: str) -> AuditRecord | None:
        m = _LOG_LINE.match(line)
        if m is None or (m.group(1) not in AVC_TYPES and m.group(1) not in NETLINK_TYPES.values()):
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

    def health(self) -> dict[str, object]:
        return {"source": self._source.name if self._source else None}

    def _publish(self, events: list[AvcEvent]) -> None:
        for ev in events:
            cgroup = self._fs.pid_cgroup(ev.pid) if ev.pid is not None else None
            unit = self._fs.unit_of(cgroup) if cgroup else None
            self._queue.put_nowait(
                dataclasses.replace(ev, cgroup_at_receipt=cgroup, unit_at_receipt=unit)
            )

    def _now(self) -> float:
        return self._clock() / 1_000_000

    async def _flusher(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            try:
                self._publish(self._asm.flush(self._now()))
            except Exception:
                log.exception("audit flush failed")

    async def run(self) -> None:
        self._source = self._factory()
        flusher = asyncio.create_task(self._flusher())
        try:
            async for rec in self._source.records():
                try:
                    self._publish(self._asm.feed(rec, self._now()))
                except Exception:
                    log.exception("audit record handling failed")
        finally:
            flusher.cancel()
