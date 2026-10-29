"""Turns the raw event stream into incidents.

Three kinds come out of here: a unit failure with the SELinux denials that
plausibly caused it, a PSI stall that outlasted its policy's `sustained`
period, and a burst of denials for one domain. Everything is driven by the
timestamps on the events and the `now_us` passed to `tick`, so the class is
deterministic and does no I/O.
"""

from __future__ import annotations

import bisect
import math
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from itertools import islice

from .config_types import CorrelationConfig
from .events import AvcEvent, Correlation, Event, Incident, PsiEvent, UnitEvent
from .ids import uuid7
from .policy import PsiWhen, target_matches

_S = 1_000_000
# Audit stamps are millisecond-truncated, so a denial can read up to 999 µs
# earlier than the journal clock would have recorded it.
_AUDIT_SLACK_US = 999
_MAX_DOMAINS = 4096
# A failure waits for the audit stream to be read past its window, plus this
# much for records still on their way from the kernel...
AUDIT_SETTLE_US = 200_000
# ...but no longer than this; then it goes out marked audit_caught_up=False.
AUDIT_WAIT_MAX_US = 30_000_000

# ExecStart basenames, SELinux domain if known, and the last main PID
UnitInfo = Callable[[str], tuple[set[str], str | None, int | None]]


def _no_unit_info(unit: str) -> tuple[set[str], str | None, int | None]:
    return set(), None, None


def _ts(ev: Event) -> int:
    return ev.ts_us


def _exec_names(avc: AvcEvent) -> set[str]:
    names = set()
    if avc.comm:
        # systemd names a process it is about to exec "(cmd)"
        comm = avc.comm
        names.add(comm[1:-1] if comm.startswith("(") and comm.endswith(")") else comm)
    # a denied exec is reported against systemd-executor, which says nothing
    if avc.exe and not avc.exe.startswith("/usr/lib/systemd/"):
        names.add(avc.exe.rsplit("/", 1)[-1])
    return names


def _leaf(cgroup: str | None) -> str:
    return (cgroup or "").rstrip("/").rsplit("/", 1)[-1]


def score(
    avc: AvcEvent,
    unit: str,
    unit_domain: str | None,
    exec_names: set[str],
    main_pid: int | None = None,
) -> Correlation | None:
    """How likely `avc` belongs to `unit`, or None if nothing links them."""
    if avc.unit_at_receipt is not None and avc.unit_at_receipt != unit:
        # The process was seen in another unit, so a shared domain or binary
        # (a sibling template instance, say) points away from this one.
        return None
    found: list[tuple[str, float]] = []
    if unit in (avc.unit_at_receipt, _leaf(avc.cgroup_at_receipt)):
        found.append(("pid in unit cgroup", 0.9))
    elif avc.cgroup_at_receipt is None and main_pid is not None and avc.pid == main_pid:
        # gone before its cgroup could be read, but systemd remembers it
        found.append(("pid was the unit's main process", 0.9))
    elif unit in (avc.parent_unit_at_receipt, _leaf(avc.parent_cgroup_at_receipt)):
        # a child starts in its parent's cgroup, but the parent can move it: weaker
        found.append(("parent pid in unit cgroup", 0.8))
    elif avc.cgroup_at_receipt is None and main_pid is not None and avc.ppid == main_pid:
        found.append(("parent was the unit's main process", 0.8))
    if unit_domain is not None and avc.scontext_type == unit_domain:
        found.append(("scontext type matches unit domain", 0.6))
    if _exec_names(avc) & exec_names:
        found.append(("comm matches ExecStart", 0.4))
    if not found:
        return None
    confidence = 1 - math.prod(1 - w for _, w in found)
    return Correlation(avc, round(confidence, 4), tuple(r for r, _ in found))


@dataclass
class _Episode:
    start_us: int
    last_us: int
    fired: set[float] = field(default_factory=set)  # sustained periods already reported


def _is_self_or_ancestor(candidate: str, cgroup: str) -> bool:
    parent, child = candidate.strip("/"), cgroup.strip("/")
    return not parent or parent == child or child.startswith(parent + "/")


class Correlator:
    """Holds the last `retention` seconds of events and emits incidents.

    `ingest` returns incidents that are complete on arrival (PSI, AVC
    bursts). Unit failures wait `after` seconds for late denials and come
    out of `tick`, once the audit stream has been read past their window
    (see `tick`). `unit_info` maps a unit to its ExecStart basenames, its
    SELinux domain and its last main PID, where known; the caller resolves
    these ahead of time.
    """

    def __init__(
        self,
        cfg: CorrelationConfig,
        psi_whens: Sequence[PsiWhen],
        clock: Callable[[], float],
        unit_info: UnitInfo = _no_unit_info,
    ) -> None:
        self._clock = clock
        self._unit_info = unit_info
        self.configure(cfg, psi_whens)
        self._events: deque[Event] = deque()
        self._pending: list[UnitEvent] = []
        self._domains: dict[str, tuple[int, str]] = {}  # unit -> (ts_us, scontext type)
        self._episodes: dict[tuple[str, str, str, int, int], _Episode] = {}
        self._samples: dict[tuple[str, str, str], PsiEvent] = {}
        self._avc_latched_until: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._events)

    def configure(self, cfg: CorrelationConfig, psi_whens: Sequence[PsiWhen]) -> None:
        """Apply new settings (on reload); buffered events and pending failures are kept."""
        self._cfg = cfg
        self._whens = tuple(psi_whens)
        self._retention_us = int(cfg.retention * _S)
        self._before_us = int(cfg.before * _S)
        self._after_us = int(cfg.after * _S)

    def ingest(self, ev: Event) -> list[Incident]:
        if not self._events or ev.ts_us >= self._events[-1].ts_us:
            self._events.append(ev)
        else:
            bisect.insort(self._events, ev, key=_ts)
        self._evict(int(self._clock() * _S))
        match ev:
            case UnitEvent():
                self._on_unit(ev)
                return []
            case AvcEvent():
                return self._on_avc(ev)
            case PsiEvent():
                return self._on_psi(ev)

    def tick(self, now_us: int, audit_until_us: int | None = None) -> list[Incident]:
        """Finalise unit failures whose `after` window has closed.

        `audit_until_us` is how far the audit stream has been read and
        ingested. Under load the daemon can fall seconds behind it, so a
        failure also waits until audit has caught up past its window, for
        at most AUDIT_WAIT_MAX_US. None (no audit collector) doesn't wait.
        """
        self._evict(now_us)
        out, waiting = [], []
        for f in self._pending:
            hi = f.ts_us + self._after_us
            caught_up = audit_until_us is None or audit_until_us >= hi + AUDIT_SETTLE_US
            if now_us >= hi and (caught_up or now_us >= hi + AUDIT_WAIT_MAX_US):
                out.append(self._finalise(f, caught_up))
            else:
                waiting.append(f)
        self._pending = waiting
        return out

    # -- internals ---------------------------------------------------------

    def _evict(self, now_us: int) -> None:
        horizon = now_us - self._retention_us
        while self._events and self._events[0].ts_us < horizon:
            self._events.popleft()
        self._samples = {k: s for k, s in self._samples.items() if s.ts_us >= horizon}
        self._episodes = {k: e for k, e in self._episodes.items() if e.last_us >= horizon}
        self._avc_latched_until = {
            t: until for t, until in self._avc_latched_until.items() if until >= now_us
        }

    def _window(self, lo_us: int, hi_us: int) -> Iterable[Event]:
        """Events with lo_us <= ts_us <= hi_us."""
        i = bisect.bisect_left(self._events, lo_us, key=_ts)
        j = bisect.bisect_right(self._events, hi_us, key=_ts)
        return islice(self._events, i, j)

    def _on_unit(self, ev: UnitEvent) -> None:
        if ev.kind == "exited":
            return
        # The "unit failed" message carries the result policies filter on, so it
        # takes over from a "job failed" for the same invocation still pending.
        if ev.kind == "failed":
            for i, p in enumerate(self._pending):
                if p.kind == "start_failed" and self._same_invocation(p, ev):
                    self._pending[i] = ev
                    return
        # systemd logs both "unit failed" and "job failed" for one failed start
        if any(
            isinstance(e, UnitEvent) and e.kind != "exited" and self._same_invocation(e, ev)
            for e in self._events
        ):
            return
        self._pending.append(ev)

    @staticmethod
    def _same_invocation(e: Event, f: UnitEvent) -> bool:
        return (
            isinstance(e, UnitEvent)
            and e is not f
            and e.unit == f.unit
            and f.invocation_id is not None
            and e.invocation_id == f.invocation_id
        )

    def _finalise(self, failure: UnitEvent, audit_caught_up: bool = True) -> Incident:
        exec_names, domain, main_pid = self._unit_info(failure.unit)
        lo = failure.ts_us - self._before_us - _AUDIT_SLACK_US
        hi = failure.ts_us + self._after_us
        correlations = []
        for ev in self._window(lo, hi):
            if not (isinstance(ev, AvcEvent) and ev.denied):
                continue
            learned = domain or self._learned_domain(failure.unit, ev.ts_us)
            c = score(ev, failure.unit, learned, exec_names, main_pid)
            if c is not None and c.confidence >= self._cfg.min_confidence:
                correlations.append(c)
        related = tuple(e for e in self._events if self._same_invocation(e, failure))
        return Incident(
            uuid7(),
            "unit_failed",
            failure.ts_us,
            failure.unit,
            failure,
            related,
            tuple(correlations),
            audit_caught_up=audit_caught_up,
        )

    def _learned_domain(self, unit: str, before_us: int) -> str | None:
        """Domain of the unit's most recent denial strictly before `before_us`.

        Strictly before, so a denial never vouches for itself.
        """
        known = self._domains.get(unit)
        if known is not None and known[0] < before_us:
            return known[1]
        i = bisect.bisect_left(self._events, before_us, key=_ts)
        # Known limit: walks back through older events, but only for AVCs in a
        # failure window (upgrade path: index the newest denial per unit).
        for k in range(i - 1, -1, -1):
            ev = self._events[k]
            if isinstance(ev, AvcEvent) and ev.unit_at_receipt == unit:
                return ev.scontext_type
        return None

    def _on_avc(self, ev: AvcEvent) -> list[Incident]:
        unit = ev.unit_at_receipt
        if unit is not None and ev.ts_us >= self._domains.get(unit, (-1, ""))[0]:
            self._domains.pop(unit, None)
            self._domains[unit] = (ev.ts_us, ev.scontext_type)
            if len(self._domains) > _MAX_DOMAINS:
                del self._domains[next(iter(self._domains))]
        if not ev.denied:
            return []
        stype = ev.scontext_type
        if ev.ts_us <= self._avc_latched_until.get(stype, -1):
            return []
        burst = [
            e
            for e in self._window(ev.ts_us - self._before_us, ev.ts_us)
            if isinstance(e, AvcEvent) and e.denied and e.scontext_type == stype
        ]
        if len(burst) < self._cfg.avc_burst:
            return []
        self._avc_latched_until[stype] = ev.ts_us + self._retention_us
        related = tuple(e for e in burst if e is not ev)
        return [Incident(uuid7(), "avc", ev.ts_us, stype, ev, related, ())]

    def _on_psi(self, ev: PsiEvent) -> list[Incident]:
        if not ev.triggered:
            self._samples[(ev.cgroup, ev.resource, ev.kind)] = ev
            return []
        whens = [
            w
            for w in self._whens
            if (w.resource, w.kind, w.stall_us, w.window_us)
            == (ev.resource, ev.kind, ev.stall_us, ev.window_us)
            and any(target_matches(p, ev.cgroup) for p in w.cgroups)
        ]
        if not whens:
            return []
        window_us = whens[0].window_us
        key = (ev.cgroup, ev.resource, ev.kind, whens[0].stall_us, window_us)
        # Triggers fire at most once per window, so a silence of two windows
        # (at least 2 s) means the stall has eased and the episode is over.
        gap_us = max(2 * window_us, 2 * _S)
        ep = self._episodes.get(key)
        if ep is None or ev.ts_us - ep.last_us > gap_us:
            ep = self._episodes[key] = _Episode(ev.ts_us, ev.ts_us)
        ep.last_us = max(ep.last_us, ev.ts_us)
        elapsed_us = ev.ts_us - ep.start_us
        due = sorted(
            s for s in {w.sustained for w in whens} if s not in ep.fired and elapsed_us >= s * _S
        )
        if not due:
            return []
        ep.fired.update(due)
        related = tuple(
            s for (cg, _, _), s in self._samples.items() if _is_self_or_ancestor(cg, ev.cgroup)
        )
        return [
            Incident(uuid7(), "psi", ev.ts_us, ev.cgroup, ev, related, (), sustained=s) for s in due
        ]
