"""Prometheus text exposition (format 0.0.4) and a tiny localhost HTTP server.

Thread-safety: metrics are updated only from the event loop thread, so there
are no locks. Callers on other threads must hop onto the loop first.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

log = logging.getLogger(__name__)

PSI_AVG10 = "sentry_v2_psi_avg10"
ACTIONS_TOTAL = "sentry_v2_actions_total"
ACTIONS_ACTIVE = "sentry_v2_actions_active"
INCIDENTS_TOTAL = "sentry_v2_incidents_total"
AVC_CORRELATED_TOTAL = "sentry_v2_avc_correlated_total"
EVENTS_DROPPED_TOTAL = "sentry_v2_events_dropped_total"
SINK_FAILURES_TOTAL = "sentry_v2_sink_failures_total"
BUILD_INFO = "sentry_v2_build_info"
RENDER_ERRORS_TOTAL = "sentry_v2_metrics_render_errors_total"

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
MAX_HEADER_BYTES = 4096
HEADER_TIMEOUT = 5.0
WRITE_TIMEOUT = 5.0
LOG_INTERVAL = 60.0

_NAME_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_LABEL_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")

Labels = dict[str, str]


def _fmt(v: float) -> str:
    if v != v:
        return "NaN"
    if v in (float("inf"), float("-inf")):
        return "+Inf" if v > 0 else "-Inf"
    return repr(float(v))


def _check_label(label: str) -> None:
    if not _LABEL_RE.fullmatch(label) or label.startswith("__"):
        raise ValueError(f"invalid label name: {label!r}")


def _escape_help(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_value(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _sample(name: str, names: tuple[str, ...], values: tuple[str, ...], v: float) -> str:
    if not names:
        return f"{name} {_fmt(v)}\n"
    pairs = ",".join(f'{n}="{_escape_value(x)}"' for n, x in zip(names, values, strict=True))
    return f"{name}{{{pairs}}} {_fmt(v)}\n"


class _Child:
    def __init__(self, monotonic: bool) -> None:
        self.value = 0.0
        self._monotonic = monotonic

    def inc(self, n: float = 1) -> None:
        if self._monotonic and n < 0:
            raise ValueError("counters cannot decrease")
        self.value += n

    def set(self, v: float) -> None:
        if self._monotonic:
            raise ValueError("counters cannot be set")
        self.value = float(v)


class _Metric:
    kind = ""

    def __init__(self, name: str, help: str, labelnames: tuple[str, ...]) -> None:
        self.name = name
        self.help = help
        self.labelnames = labelnames
        self._children: dict[tuple[str, ...], _Child] = {}
        if not labelnames and self.kind == "counter":
            self.labels()  # render 0 from the first scrape

    def labels(self, **kw: str) -> _Child:
        if set(kw) != set(self.labelnames):
            raise ValueError(f"{self.name}: expected labels {self.labelnames}, got {tuple(kw)}")
        key = tuple(str(kw[n]) for n in self.labelnames)
        child = self._children.get(key)
        if child is None:
            child = self._children[key] = _Child(self.kind == "counter")
        return child

    def _unlabelled(self) -> _Child:
        if self.labelnames:
            raise ValueError(f"{self.name} has labels; use .labels(...)")
        return self.labels()

    def inc(self, n: float = 1) -> None:
        self._unlabelled().inc(n)

    def set(self, v: float) -> None:
        self._unlabelled().set(v)

    def samples(self) -> Iterable[str]:
        for key in sorted(self._children):
            yield _sample(self.name, self.labelnames, key, self._children[key].value)


class Counter(_Metric):
    kind = "counter"


class Gauge(_Metric):
    kind = "gauge"


class _FuncGauge:
    kind = "gauge"

    def __init__(
        self,
        name: str,
        help: str,
        fn: Callable[[], Iterable[tuple[Labels, float]]],
    ) -> None:
        self.name = name
        self.help = help
        self._fn = fn

    def samples(self) -> Iterable[str]:
        rows = list(self._fn())
        if not rows:
            return iter(())
        names = tuple(sorted(rows[0][0]))
        for label in names:
            _check_label(label)
        table = []
        for labels, v in rows:
            if set(labels) != set(names):
                raise ValueError(f"{self.name}: inconsistent label set {sorted(labels)}")
            table.append((tuple(str(labels[n]) for n in names), float(v)))
        table.sort(key=lambda row: row[0])
        return iter([_sample(self.name, names, values, v) for values, v in table])


class Registry:
    """Holds metrics in registration order and renders them on demand."""

    def __init__(self) -> None:
        self._metrics: dict[str, Counter | Gauge | _FuncGauge] = {}
        # Set by build_registry; counts metrics skipped during render.
        self.render_errors: Counter | None = None
        self._last_logged: dict[str, float] = {}

    def _check(self, name: str, labelnames: tuple[str, ...] = ()) -> None:
        if not _NAME_RE.fullmatch(name):
            raise ValueError(f"invalid metric name: {name!r}")
        if name in self._metrics:
            raise ValueError(f"metric already registered: {name}")
        for label in labelnames:
            _check_label(label)

    def counter(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> Counter:
        self._check(name, labelnames)
        m = self._metrics[name] = Counter(name, help, tuple(labelnames))
        return m

    def gauge(self, name: str, help: str, labelnames: tuple[str, ...] = ()) -> Gauge:
        self._check(name, labelnames)
        m = self._metrics[name] = Gauge(name, help, tuple(labelnames))
        return m

    def gauge_func(
        self,
        name: str,
        help: str,
        fn: Callable[[], Iterable[tuple[Labels, float]]],
    ) -> None:
        """Gauge computed at scrape time; fn yields (labels, value) rows."""
        self._check(name)
        self._metrics[name] = _FuncGauge(name, help, fn)

    def _render_failed(self, name: str) -> None:
        if self.render_errors is not None:
            self.render_errors.inc()
        now = time.monotonic()
        last = self._last_logged.get(name)
        if last is None or now - last >= LOG_INTERVAL:
            self._last_logged[name] = now
            log.exception("metric %s failed to render; skipping it", name)

    def render(self) -> str:
        out: list[str] = []
        for m in self._metrics.values():
            try:
                lines = list(m.samples())
            except Exception:
                self._render_failed(m.name)
                continue
            out.append(f"# HELP {m.name} {_escape_help(m.help)}\n# TYPE {m.name} {m.kind}\n")
            out.extend(lines)
        return "".join(out)


@dataclass(frozen=True)
class Metrics:
    """Metrics the daemon updates directly.

    psi_avg10{cgroup,resource,kind} and actions_active are not here: the
    daemon registers them with Registry.gauge_func (names PSI_AVG10 and
    ACTIONS_ACTIVE) because their values live in other components.
    """

    actions_total: Counter
    incidents_total: Counter
    avc_correlated_total: Counter
    events_dropped_total: Counter
    sink_failures_total: Counter
    build_info: Gauge


def build_registry(build_info: dict[str, str]) -> tuple[Registry, Metrics]:
    r = Registry()
    m = Metrics(
        actions_total=r.counter(
            ACTIONS_TOTAL,
            "Actions attempted, by policy, action, mode and result.",
            ("policy", "action", "mode", "result"),
        ),
        incidents_total=r.counter(INCIDENTS_TOTAL, "Incidents opened, by kind.", ("kind",)),
        avc_correlated_total=r.counter(
            AVC_CORRELATED_TOTAL, "AVC denials correlated to an incident."
        ),
        events_dropped_total=r.counter(
            EVENTS_DROPPED_TOTAL, "Events dropped on queue overflow.", ("collector",)
        ),
        sink_failures_total=r.counter(SINK_FAILURES_TOTAL, "Sink delivery failures.", ("sink",)),
        build_info=r.gauge(BUILD_INFO, "Build information (always 1).", tuple(build_info)),
    )
    m.build_info.labels(**build_info).set(1)
    r.render_errors = r.counter(
        RENDER_ERRORS_TOTAL, "Metrics skipped because they failed to render."
    )
    return r, m


_REASONS = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    500: "Internal Server Error",
    431: "Request Header Fields Too Large",
}


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class MetricsServer:
    def __init__(
        self,
        registry: Registry,
        host: str,
        port: int,
        header_timeout: float = HEADER_TIMEOUT,
    ) -> None:
        self._registry = registry
        self._host = host
        self._port = port
        self._header_timeout = header_timeout
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """Bound port (useful when constructed with port 0)."""
        if self._server is None:
            raise RuntimeError("server not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        if not _is_loopback(self._host):
            log.warning("metrics endpoint binding to non-loopback address %s", self._host)
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, limit=MAX_HEADER_BYTES
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _respond(
        self, writer: asyncio.StreamWriter, status: int, body: bytes = b"", ctype: str = ""
    ) -> None:
        head = f"HTTP/1.1 {status} {_REASONS[status]}\r\nContent-Length: {len(body)}\r\n"
        if ctype:
            head += f"Content-Type: {ctype}\r\n"
        head += "Connection: close\r\n\r\n"
        writer.write(head.encode("ascii") + body)
        await asyncio.wait_for(writer.drain(), timeout=WRITE_TIMEOUT)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                raw = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=self._header_timeout
                )
            except TimeoutError:
                await self._respond(writer, 408)
                return
            except asyncio.LimitOverrunError:
                await self._respond(writer, 431)
                return
            except asyncio.IncompleteReadError:
                await self._respond(writer, 400)
                return
            parts = raw.split(b"\r\n", 1)[0].split(b" ")
            if len(parts) != 3:
                await self._respond(writer, 400)
            elif parts[0] != b"GET":
                await self._respond(writer, 405)
            elif parts[1].split(b"?", 1)[0] != b"/metrics":
                await self._respond(writer, 404)
            else:
                try:
                    body = self._registry.render().encode()
                except Exception:
                    log.exception("metrics render failed")
                    await self._respond(writer, 500)
                else:
                    await self._respond(writer, 200, body, CONTENT_TYPE)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
