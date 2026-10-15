"""sentry-v2ctl: talk to the running daemon, or check policies offline."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import time
import unicodedata
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .client import ControlClient, ControlError, NotRunning, PermissionDenied
from .config import ConfigError, load_config
from .config_types import Config
from .correlate import Correlator
from .events import AvcEvent, Event, Incident, PsiEvent, UnitEvent
from .policy import Freeze, Notify, Policy, PolicyEngine, PsiWhen, Throttle, effective_mode
from .units import Percent

DEFAULT_SOCKET = "/run/sentry-v2/control.sock"
DEFAULT_CONFIG = "/etc/sentry-v2/sentry-v2.toml"
DEFAULT_POLICIES = "/etc/sentry-v2/policies.d"
_US = 1_000_000
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_FULL_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MIN_SHORT_ID = 6
_COLOURS = {
    "failed": "31", "rollback_failed": "31", "high": "31", "critical": "31",
    "applied": "32", "ok": "32",
    "planned": "33", "dry_run": "33", "medium": "33", "warning": "33",
    "rolled_back": "36",
}  # fmt: skip


# -- output helpers -------------------------------------------------------------------


def _clean(v: object) -> str:
    """Daemon and file text is untrusted: no control characters reach the terminal."""
    text = _CONTROL.sub("?", str(v))
    return "".join("?" if unicodedata.category(c) == "Cf" else c for c in text)


def _paint(cell: str) -> str:
    if cell in _COLOURS and sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == "":
        return f"\x1b[{_COLOURS[cell]}m{cell}\x1b[0m"
    return cell


def _table(rows: list[list[str]], headers: list[str]) -> str:
    """Left-aligned columns. Cells are cleaned, padded, then status words coloured."""
    grid = [[_clean(c) for c in r] for r in (headers, *rows)]
    widths = [max(len(r[i]) for r in grid) for i in range(len(headers))]
    lines = []
    for r in grid:
        cells = [_paint(c) + " " * (w - len(c)) for c, w in zip(r, widths, strict=True)]
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines)


def _span(seconds: float) -> str:
    if not abs(seconds) < 1e9:  # also catches inf and nan
        return "a very long time"
    s = int(abs(seconds))
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m}m"
    return f"{m}m{s}s" if m else f"{s}s"


def _when(v: object) -> str:
    """Epoch seconds or RFC 3339 as "2m ago" / "in 4m12s"; empty if unset."""
    if v in (None, ""):
        return ""
    if isinstance(v, str):
        try:
            t = datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return _clean(v)
    else:
        t = float(v)  # type: ignore[arg-type]
    delta = t - time.time()
    return f"in {_span(delta)}" if delta > 0 else f"{_span(delta)} ago"


def _action_rows(records: list[dict[str, Any]]) -> list[list[str]]:
    return [
        [
            str(r.get("id", ""))[-8:],  # a UUIDv7 starts with its timestamp
            str(r.get("policy", "")),
            str(r.get("action", "")),
            str(r.get("target", "")),
            str(r.get("status", "")),
            str(r.get("mode", "")),
            _when(r.get("expires_at")) or _when(r.get("ts")),
        ]
        for r in records
    ]


_ACTION_HEAD = ["ID", "POLICY", "ACTION", "TARGET", "STATUS", "MODE", "WHEN"]


# -- daemon commands ------------------------------------------------------------------


def _status(r: dict[str, Any]) -> str:
    state = "paused" if r["paused"] else "running"
    out = [
        _clean(f"sentry-v2 {r['version']}  {state} for {_span(r['uptime_s'])}  mode {r['mode']}")
    ]
    if r.get("last_reload_error"):
        out.append(_clean(f"last reload failed: {r['last_reload_error']}"))
    out.append("")
    out.append(
        _table(
            [[n, ", ".join(f"{k}={v}" for k, v in h.items())] for n, h in r["collectors"].items()],
            ["COLLECTOR", "HEALTH"],
        )
    )
    out.append("")
    if r["active_actions"]:
        out.append(_table(_action_rows(r["active_actions"]), _ACTION_HEAD))
    else:
        out.append("no active actions")
    return "\n".join(out)


def _top(r: dict[str, Any], sort: str) -> str:
    rows = r["cgroups"]
    rows = sorted(
        rows, key=(lambda x: x["cgroup"]) if sort == "cgroup" else (lambda x: -x["avg10"])
    )
    return _table(
        [
            [x["cgroup"], x["resource"], x["kind"], f"{x['avg10']:.2f}", f"{x['avg60']:.2f}",
             f"{x['avg300']:.2f}"]
            for x in rows
        ],
        ["CGROUP", "RESOURCE", "KIND", "AVG10", "AVG60", "AVG300"],
    )  # fmt: skip


def _incidents(r: dict[str, Any]) -> str:
    rows = [
        [i["id"], _when(i["ts"]), str(i["severity"]), i["kind"], i["target"], i["policy"]]
        for i in r["incidents"]
    ]
    return _table(rows, ["ID", "WHEN", "SEVERITY", "KIND", "TARGET", "POLICY"])


def _actions(r: dict[str, Any]) -> str:
    return (
        "active\n"
        + _table(_action_rows(r["active"]), _ACTION_HEAD)
        + "\n\nrecent\n"
        + _table(_action_rows(r["recent"]), _ACTION_HEAD)
    )


def _policies(r: dict[str, Any]) -> str:
    rows = [
        [p["name"], p["mode"], p["effective_mode"], p["signal"], ", ".join(p["actions"]),
         p["source"]]
        for p in r["policies"]
    ]  # fmt: skip
    out = _table(rows, ["NAME", "MODE", "EFFECTIVE", "SIGNAL", "ACTIONS", "SOURCE"])
    if r["last_reload_error"]:
        out += "\n\n" + _clean(f"last reload failed: {r['last_reload_error']}")
    return out


def _top_loop(client: ControlClient, sort: str, as_json: bool, once: bool) -> int:
    live = sys.stdout.isatty() and not once
    try:
        while True:
            r = client.call("psi")
            text = json.dumps(r) if as_json else _top(r, sort)
            print(("\x1b[H\x1b[2J" if live else "") + text, flush=True)
            if not live:
                return 0
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


def _rolled_back(r: dict[str, Any]) -> str:
    lines = [
        _clean(f"rolled back {a['id']}  {a.get('action', '')} on {a.get('target', '')}")
        for a in r["rolled_back"]
    ]
    return "\n".join(lines) or "nothing to roll back"


def _restored(r: dict[str, Any]) -> str:
    lines = ["restored:", *r["restored"]] if r["restored"] else []
    if r.get("skipped"):
        lines += ["already matched the backup:", *r["skipped"]]
    return "\n".join(_clean(x) for x in [*lines, r["note"]])


_HUMAN: dict[str, Callable[[dict[str, Any]], str]] = {
    "status": _status,
    "incidents": _incidents,
    "actions": _actions,
    "policies": _policies,
    "show": lambda r: json.dumps(r["bundle"], indent=2),
    "rollback": _rolled_back,
    "pause": lambda r: "paused" if r["paused"] else "resumed",
    "resume": lambda r: "paused" if r["paused"] else "resumed",
    "reload": lambda r: "reloaded the configuration",
    "restore": _restored,
}


def _call_args(args: argparse.Namespace) -> dict[str, Any]:
    match args.cmd:
        case "incidents":
            given = {"since": args.since, "unit": args.unit, "limit": args.limit}
            return {k: v for k, v in given.items() if v is not None}
        case "show":
            return {"id": args.id}
        case "rollback":
            return {"all": True} if args.all else {"id": args.id}
        case "restore":
            return {"backup_id": args.backup_id}
    return {}


def _resolve_id(client: ControlClient, given: str) -> str:
    """Expand a unique prefix or suffix of a recent action's id to the full id."""
    given = given.lower()
    if _FULL_ID.fullmatch(given):
        return given
    if len(given) < MIN_SHORT_ID:
        raise ControlError(f"give at least {MIN_SHORT_ID} characters of the action id")
    acts = client.call("actions")
    ids = {str(r["id"]) for r in acts["active"] + acts["recent"]}
    matches = sorted(i for i in ids if i.startswith(given) or i.endswith(given))
    if not matches:
        raise ControlError(f"no recent action matches {given}; try the full id")
    if len(matches) > 1:
        raise ControlError(f"{given} matches more than one action: {', '.join(matches)}")
    return matches[0]


def _daemon(args: argparse.Namespace) -> int:
    client = ControlClient(Path(args.socket))
    if args.cmd == "top":
        return _top_loop(client, args.sort, args.json, args.once)
    if args.cmd == "rollback" and not args.all:
        args.id = _resolve_id(client, args.id)
    result = client.call(args.cmd, **_call_args(args))
    print(json.dumps(result) if args.json else _HUMAN[args.cmd](result))
    return 0


# -- offline policy commands ----------------------------------------------------------


def _load(args: argparse.Namespace) -> Config:
    return load_config(Path(args.config), Path(args.policies))


def _validate(args: argparse.Namespace) -> int:
    try:
        n = len(_load(args).policies)
    except ConfigError as e:
        if args.json:
            print(json.dumps({"valid": False, "error": str(e)}))
        print(f"invalid: {_clean(e)}", file=sys.stderr)
        return 1
    print(json.dumps({"valid": True, "policies": n}) if args.json else f"ok: {n} policies")
    return 0


def _event(d: dict[str, Any], default_ts: int) -> Event:
    d = dict(d)
    kind = d.pop("kind", None)
    d.setdefault("ts_us", default_ts)
    match kind:
        case "unit_failed":
            return UnitEvent(kind="failed", **d)
        case "psi":
            d["kind"] = d.pop("pressure", "full")
            return PsiEvent(**d)
        case "avc":
            d["perms"] = tuple(d.get("perms", ()))
            return AvcEvent(**d)
    raise ValueError(f'"kind" must be unit_failed, psi or avc, not {kind!r}')


def _ramp(ev: PsiEvent, whens: list[PsiWhen]) -> list[PsiEvent]:
    """A lone PSI trigger can't outlast `sustained`, so replay it up to the policy period."""
    out: list[PsiEvent] = []
    for w in whens:
        if (w.resource, w.kind, w.stall_us, w.window_us) != (
            ev.resource,
            ev.kind,
            ev.stall_us,
            ev.window_us,
        ):
            continue
        t = ev.ts_us - int(w.sustained * _US)
        while t < ev.ts_us:
            out.append(replace(ev, ts_us=t))
            t += w.window_us
    return sorted(out, key=lambda e: e.ts_us)


def _incidents_from(events: list[Event], cfg: Config) -> list[Incident]:
    whens = [p.when for p in cfg.policies if isinstance(p.when, PsiWhen)]
    now = [0.0]
    cor = Correlator(cfg.correlation, whens, lambda: now[0])
    if len(events) == 1 and isinstance(events[0], PsiEvent):
        events = [*_ramp(events[0], whens), *events]
    found: list[Incident] = []
    for ev in events:
        now[0] = max(now[0], ev.ts_us / _US)
        found += cor.ingest(ev)
    end = max(e.ts_us for e in events) + int((cfg.correlation.after + 1) * _US)
    return found + cor.tick(end)


def _spec(spec: object) -> tuple[str, str]:
    match spec:
        case Throttle():
            mh = spec.memory_high
            parts = {
                "memory_high": f"{mh.value:g}%" if isinstance(mh, Percent) else mh,
                "cpu_weight": spec.cpu_weight,
            }
            parts["duration"] = f"{_span(spec.duration)}"
            return "throttle", " ".join(f"{k}={v}" for k, v in parts.items() if v is not None)
        case Freeze():
            return "freeze", f"duration={_span(spec.duration)}"
        case Notify():
            return "notify", ""
        case _:
            return "backup_reload", " ".join(str(p) for p in getattr(spec, "paths", ()))


def _plan(args: argparse.Namespace) -> list[dict[str, str]]:
    cfg = _load(args)
    raw = json.loads(Path(args.event).read_text())
    now_us = int(time.time() * _US)
    events = [_event(d, now_us) for d in (raw if isinstance(raw, list) else [raw])]
    if not events:
        raise ValueError("it holds no events")
    engine = PolicyEngine(cfg.policies, lambda: 0.0)
    plans = []
    for inc in _incidents_from(events, cfg):
        for pol, spec in engine.plan(inc):
            action, detail = _spec(spec)
            plans.append(_plan_row(pol, inc, action, detail, cfg))
    return plans


def _plan_row(pol: Policy, inc: Incident, action: str, detail: str, cfg: Config) -> dict[str, str]:
    return {
        "policy": pol.name,
        "target": inc.target,
        "action": action,
        "params": detail,
        "mode": effective_mode(cfg.daemon.mode, pol.mode),
    }


def _test(args: argparse.Namespace) -> int:
    try:
        plans = _plan(args)
    except ConfigError as e:
        print(f"invalid: {_clean(e)}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError) as e:
        print(
            f"cannot use {_clean(args.event)}: {_clean(e)}. Expected a JSON event or a list.",
            file=sys.stderr,
        )
        return 1
    if args.json:
        print(json.dumps(plans))
    elif not plans:
        print("no policy matches this event")
    else:
        heads = ["POLICY", "TARGET", "ACTION", "PARAMS", "MODE"]
        print(_table([[p[k.lower()] for k in heads] for p in plans], heads))
    return 0


# -- entry point ----------------------------------------------------------------------


def _positive(v: str) -> int:
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--socket", default=argparse.SUPPRESS, help=f"control socket (default {DEFAULT_SOCKET})"
    )
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print JSON instead of tables",
    )
    p = argparse.ArgumentParser(
        prog="sentry-v2ctl", description="Inspect and control sentry-v2.", parents=[common]
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, help: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help, parents=[common])

    add("status", "daemon mode, collectors and active actions")
    t = add("top", "cgroups under the most pressure")
    t.add_argument("--once", action="store_true", help="print one snapshot and exit")
    t.add_argument("--sort", choices=["avg10", "cgroup"], default="avg10")
    i = add("incidents", "recent incidents, newest first")
    i.add_argument("--since", help="only incidents after this RFC 3339 time")
    i.add_argument("--unit", help="only incidents for this unit")
    i.add_argument("--limit", type=_positive, help="how many to show (daemon default 50)")
    add("show", "full bundle for one incident").add_argument("id")
    add("actions", "active and recent actions")
    add("policies", "loaded policies and the last reload error")
    r = add("rollback", "undo an action now")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("id", nargs="?", help="action id, or a unique 6+ character start or end of one")
    g.add_argument("--all", action="store_true", help="undo every active action")
    add("pause", "stop applying actions; keep watching")
    add("resume", "start applying actions again")
    add("reload", "re-read the configuration")
    add("restore", "put back files saved by a backup_reload action").add_argument(
        "backup_id", help="<unit>/<YYYYmmddTHHMMSSZ>"
    )
    pol = add("policy", "check policies without the daemon").add_subparsers(
        dest="sub", required=True
    )
    for name, help in (
        ("validate", "load the configuration and report errors"),
        ("test", "show what an event would trigger"),
    ):
        s = pol.add_parser(name, help=help, parents=[common])
        s.add_argument("--config", default=DEFAULT_CONFIG)
        s.add_argument("--policies", default=DEFAULT_POLICIES, help="policies.d directory")
        if name == "test":
            s.add_argument(
                "--event",
                required=True,
                metavar="FILE",
                help="JSON event or list; kind is unit_failed, psi or avc",
            )
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv, argparse.Namespace(socket=DEFAULT_SOCKET, json=False))
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) else 2
    try:
        if args.cmd == "policy":
            return _validate(args) if args.sub == "validate" else _test(args)
        return _daemon(args)
    except NotRunning as e:
        print(_clean(e), file=sys.stderr)
        return 2
    except PermissionDenied as e:
        print(_clean(e), file=sys.stderr)
        return 3
    except ControlError as e:
        print(f"error: {_clean(e)}", file=sys.stderr)
        return 3 if str(e).startswith("permission denied") else 1
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as e:
        print(f"unexpected reply from the daemon: {_clean(repr(e))}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        with contextlib.suppress(OSError, ValueError):  # keep the exit-time flush quiet
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
