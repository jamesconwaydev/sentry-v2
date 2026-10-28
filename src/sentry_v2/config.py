"""Load and strictly validate the global config and policy files."""

from __future__ import annotations

import os
import posixpath
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from .config_types import (
    Config,
    ControlConfig,
    CorrelationConfig,
    DaemonConfig,
    ElasticSinkConfig,
    FileSinkConfig,
    LimitsConfig,
    MetricsConfig,
    ProtectionConfig,
    RedactionConfig,
    SinksConfig,
    SplunkHecSinkConfig,
    SyslogSinkConfig,
    WebhookSinkConfig,
)
from .policy import (
    ActionSpec,
    AvcWhen,
    BackupReload,
    Freeze,
    Mode,
    Notify,
    Policy,
    PsiWhen,
    Throttle,
    UnitFailedWhen,
    When,
    is_protected,
)
from .units import Percent, parse_duration, parse_size

T = TypeVar("T")
_NO_STRS: tuple[str, ...] = ()
_SECRET_KEYS = frozenset({"token", "password", "api_key", "hmac_key", "secret"})


class ConfigError(Exception):
    def __init__(self, file: Path, key: str, message: str) -> None:
        super().__init__(f"{file.name}: {key}: {message}")
        self.file = file
        self.key = key
        self.message = message


# --- value converters: raise ValueError(message) -------------------------------------


def _str(v: object) -> str:
    if not isinstance(v, str):
        raise ValueError("must be a string")
    return v


def _int(v: object) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError("must be an integer")
    return v


def _int_in(lo: int, hi: int) -> Callable[[object], int]:
    def conv(v: object) -> int:
        n = _int(v)
        if not lo <= n <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return n

    return conv


def _float_in(lo: float, hi: float) -> Callable[[object], float]:
    def conv(v: object) -> float:
        if isinstance(v, bool) or not isinstance(v, int | float):
            raise ValueError("must be a number")
        if not lo <= v <= hi:
            raise ValueError(f"must be between {lo:g} and {hi:g}")
        return float(v)

    return conv


def _pos_duration(v: object) -> float:
    d = _duration(v)
    if d <= 0:
        raise ValueError("must be above 0")
    return d


def _bool(v: object) -> bool:
    if not isinstance(v, bool):
        raise ValueError("must be true or false")
    return v


def _strs(v: object) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
        raise ValueError("must be a list of strings")
    return tuple(v)


def _abs_path(v: str) -> str:
    if not v.startswith("/") or posixpath.normpath(v) != v:
        raise ValueError(f"{v!r}: paths must be absolute, normalised paths")
    return v


def _abs_paths(v: object) -> tuple[Path, ...]:
    return tuple(Path(_abs_path(p)) for p in _strs(v))


def _path(v: object) -> Path:
    return Path(_abs_path(_str(v)))


def _duration(v: object) -> float:
    return parse_duration(_str(v))


def _size(v: object) -> int | Percent:
    return parse_size(_str(v))


def _bytes(v: object) -> int:
    size = _size(v)
    if isinstance(size, Percent):
        raise ValueError("must be an absolute size, not a percentage")
    return size


def _mode(v: object) -> Mode:
    return cast(Mode, _choice("dry-run", "enforce")(v))


def _choice(*options: str) -> Callable[[object], Any]:
    def conv(v: object) -> str:
        if v not in options:
            quoted = [repr(o) for o in options]
            raise ValueError("must be " + ", ".join(quoted[:-1]) + " or " + quoted[-1])
        return str(v)

    return conv


# --- table reader --------------------------------------------------------------------


class _Reader:
    """Pops known keys off a TOML table and reports whatever is left as unknown."""

    def __init__(self, table: dict[str, Any], file: Path, prefix: str = "") -> None:
        self.table = dict(table)
        self.file = file
        self.prefix = prefix

    def key(self, name: str) -> str:
        return f"{self.prefix}.{name}" if self.prefix else name

    def error(self, name: str, message: str) -> ConfigError:
        return ConfigError(self.file, self.key(name), message)

    def get(self, name: str, conv: Callable[[object], T], default: T) -> T:
        if name not in self.table:
            return default
        try:
            return conv(self.table.pop(name))
        except ValueError as e:
            raise self.error(name, str(e)) from None

    def require(self, name: str, conv: Callable[[object], T]) -> T:
        if name not in self.table:
            raise self.error(name, "is required")
        try:
            return conv(self.table.pop(name))
        except ValueError as e:
            raise self.error(name, str(e)) from None

    def sub(self, name: str) -> _Reader | None:
        if name not in self.table:
            return None
        value = self.table.pop(name)
        if not isinstance(value, dict):
            raise self.error(name, "must be a table")
        return _Reader(value, self.file, self.key(name))

    def tables(self, name: str) -> list[_Reader]:
        value = self.table.pop(name, [])
        if not isinstance(value, list) or not all(isinstance(i, dict) for i in value):
            raise self.error(name, "must be an array of tables")
        return [_Reader(t, self.file, f"{self.key(name)}[{i}]") for i, t in enumerate(value)]

    def reject_secrets(self) -> None:
        for name in self.table:
            if name in _SECRET_KEYS:
                raise self.error(name, f"secrets must be given as {name}_file")

    def finish(self, what: Literal["key", "section"] = "key") -> None:
        for name in self.table:
            raise self.error(name, f"unknown {what}")


# --- global sections -----------------------------------------------------------------


def _section(root: _Reader, name: str) -> _Reader:
    return root.sub(name) or _Reader({}, root.file, name)


def _daemon(root: _Reader) -> DaemonConfig:
    r, d = _section(root, "daemon"), DaemonConfig()
    out = DaemonConfig(
        log_level=r.get("log_level", _choice("debug", "info", "warning", "error"), d.log_level),
        state_dir=r.get("state_dir", _path, d.state_dir),
        queue_size=r.get("queue_size", _int_in(1, 10**7), d.queue_size),
        mode=r.get("mode", _mode, d.mode),
    )
    r.finish()
    return out


def _limits(root: _Reader) -> LimitsConfig:
    r, d = _section(root, "limits"), LimitsConfig()
    out = LimitsConfig(
        max_active_actions=r.get("max_active_actions", _int_in(1, 1000), d.max_active_actions),
        max_concurrent_freezes=r.get(
            "max_concurrent_freezes", _int_in(0, 1000), d.max_concurrent_freezes
        ),
        max_action_duration=r.get("max_action_duration", _pos_duration, d.max_action_duration),
        breaker_failures=r.get("breaker_failures", _int_in(1, 1000), d.breaker_failures),
        breaker_window=r.get("breaker_window", _pos_duration, d.breaker_window),
        breaker_cooldown=r.get("breaker_cooldown", _pos_duration, d.breaker_cooldown),
        flap_actions=r.get("flap_actions", _int_in(0, 1000), d.flap_actions),
        flap_window=r.get("flap_window", _pos_duration, d.flap_window),
    )
    r.finish()
    return out


def _correlation(root: _Reader) -> CorrelationConfig:
    r, d = _section(root, "correlation"), CorrelationConfig()
    out = CorrelationConfig(
        retention=r.get("retention", _pos_duration, d.retention),
        before=r.get("before", _pos_duration, d.before),
        after=r.get("after", _pos_duration, d.after),
        min_confidence=r.get("min_confidence", _float_in(0, 1), d.min_confidence),
        avc_burst=r.get("avc_burst", _int_in(1, 10**6), d.avc_burst),
    )
    r.finish()
    return out


def _redaction(root: _Reader) -> RedactionConfig:
    r = _section(root, "redaction")
    patterns = r.get("patterns", _strs, _NO_STRS)
    for p in patterns:
        try:
            re.compile(p)
        except re.error as e:
            raise r.error("patterns", f"invalid regex {p!r}: {e}") from None
    out = RedactionConfig(patterns=patterns, use_defaults=r.get("use_defaults", _bool, True))
    r.finish()
    return out


def _url(r: _Reader) -> str:
    url = r.require("url", _str)
    if not url.startswith("https://"):
        raise r.error("url", "must start with https://")
    return url


def _sinks(root: _Reader, state_dir: Path) -> SinksConfig:
    r = _section(root, "sinks")
    for name in ("file", "webhook", "syslog", "splunk_hec", "elastic"):
        sub = r.table.get(name)
        if isinstance(sub, dict):
            _Reader(sub, r.file, r.key(name)).reject_secrets()

    fd = FileSinkConfig()
    f = _section(r, "file")
    file = FileSinkConfig(
        dir=f.get("dir", _path, state_dir / "bundles"),
        max_age=f.get("max_age", _duration, fd.max_age),
        max_size=f.get("max_size", _bytes, fd.max_size),
    )
    f.finish()

    webhook = None
    if w := r.sub("webhook"):
        webhook = WebhookSinkConfig(
            url=_url(w),
            hmac_key_file=w.require("hmac_key_file", _path),
            ca_file=w.get("ca_file", _path, None),
            timeout=w.get("timeout", _duration, 10.0),
        )
        w.finish()

    syslog = None
    if s := r.sub("syslog"):
        sd = SyslogSinkConfig()
        syslog = SyslogSinkConfig(
            host=s.get("host", _str, sd.host),
            port=s.get("port", _int_in(1, 65535), sd.port),
            transport=s.get("transport", _choice("udp", "tcp", "tls"), sd.transport),
            ca_file=s.get("ca_file", _path, None),
        )
        s.finish()

    splunk = None
    if h := r.sub("splunk_hec"):
        splunk = SplunkHecSinkConfig(
            url=_url(h),
            token_file=h.require("token_file", _path),
            index=h.get("index", _str, None),
            ca_file=h.get("ca_file", _path, None),
        )
        h.finish()

    elastic = None
    if e := r.sub("elastic"):
        elastic = ElasticSinkConfig(
            url=_url(e),
            index=e.require("index", _str),
            api_key_file=e.get("api_key_file", _path, None),
            username=e.get("username", _str, None),
            password_file=e.get("password_file", _path, None),
            ca_file=e.get("ca_file", _path, None),
        )
        e.finish()
        has_key = elastic.api_key_file is not None
        has_basic = elastic.username is not None or elastic.password_file is not None
        if has_key == has_basic:
            raise e.error(
                "api_key_file", "give exactly one of api_key_file or username + password_file"
            )
        if has_basic and (elastic.username is None or elastic.password_file is None):
            raise e.error("username", "username and password_file must be given together")

    r.finish("section")
    return SinksConfig(
        file=file, webhook=webhook, syslog=syslog, splunk_hec=splunk, elastic=elastic
    )


def _metrics(root: _Reader) -> MetricsConfig:
    r, d = _section(root, "metrics"), MetricsConfig()
    out = MetricsConfig(
        enabled=r.get("enabled", _bool, d.enabled),
        host=r.get("host", _str, d.host),
        port=r.get("port", _int_in(1, 65535), d.port),
    )
    r.finish()
    return out


def _control(root: _Reader) -> ControlConfig:
    r, d = _section(root, "control"), ControlConfig()
    out = ControlConfig(
        socket=r.get("socket", _path, d.socket),
        group=r.get("group", _str, d.group),
        admin_group=r.get("admin_group", _str, d.admin_group),
    )
    r.finish()
    return out


# --- policies ------------------------------------------------------------------------


_THRESHOLD = re.compile(r"^([^/]+)/([^/]+)$")


def _threshold(v: object) -> tuple[int, int]:
    m = _THRESHOLD.match(_str(v))
    if m is None:
        raise ValueError("must look like '150ms/1s' (stall/window)")
    stall, window = parse_duration(m.group(1)), parse_duration(m.group(2))
    if not 0.5 <= window <= 10:
        raise ValueError("window must be between 500ms and 10s (kernel limit)")
    # Without CAP_SYS_RESOURCE the kernel only accepts trigger windows that
    # are a multiple of 2s, and the unit deliberately drops that capability.
    if round(window * 1_000_000) % 2_000_000:
        raise ValueError(
            "window must be a multiple of 2s (shorter or odd windows need CAP_SYS_RESOURCE)"
        )
    if not 0 < stall <= window:
        raise ValueError("stall must be above 0 and no longer than the window")
    return round(stall * 1_000_000), round(window * 1_000_000)


def _only_protected(patterns: tuple[str, ...], extra: tuple[str, ...]) -> bool:
    # Static sanity check on the unit-name part only; the runtime is_protected
    # check on the resolved target is the real guard.
    return bool(patterns) and all(is_protected(p.rsplit("/", 1)[-1], extra) for p in patterns)


def _patterns(r: _Reader, name: str, protected: tuple[str, ...]) -> tuple[str, ...]:
    patterns = r.require(name, _strs)
    if not patterns:
        raise r.error(name, "must not be empty")
    if _only_protected(patterns, protected):
        raise r.error(name, "only matches protected units")
    return patterns


def _when(r: _Reader, protected: tuple[str, ...], avc_burst: int) -> When:
    signal = r.require("signal", _choice("psi", "unit_failed", "avc"))
    when: When
    if signal == "psi":
        stall_us, window_us = r.require("threshold", _threshold)
        when = PsiWhen(
            resource=r.require("resource", _choice("memory", "cpu", "io")),
            kind=r.get("kind", _choice("some", "full"), "some"),
            stall_us=stall_us,
            window_us=window_us,
            sustained=r.get("sustained", _duration, 5.0),
            cgroups=_patterns(r, "cgroups", protected),
        )
    elif signal == "unit_failed":
        when = UnitFailedWhen(
            units=_patterns(r, "units", protected), results=r.get("results", _strs, _NO_STRS)
        )
    else:
        when = AvcWhen(
            scontext_types=r.get("scontext_types", _strs, _NO_STRS),
            min_count=r.get("min_count", _int_in(1, 10**6), 1),
        )
        # a burst incident is raised once avc_burst denials are seen, so a
        # higher min_count could never be met
        if when.min_count > avc_burst:
            raise r.error("min_count", f"must be at most correlation.avc_burst ({avc_burst})")
    r.finish()
    return when


def _action(r: _Reader, limits: LimitsConfig) -> ActionSpec:
    def duration() -> float:
        d = r.require("duration", _duration)
        cap = limits.max_action_duration
        if not 0 < d <= cap:
            raise r.error("duration", f"must be above 0 and at most max_action_duration ({cap:g}s)")
        return d

    kind = r.require("action", _choice("throttle", "freeze", "backup_reload", "notify"))
    action: ActionSpec
    if kind == "throttle":
        action = Throttle(
            memory_high=r.get("memory_high", _size, None),
            cpu_weight=r.get("cpu_weight", _int_in(1, 10000), None),
            duration=duration(),
        )
        if action.memory_high is None and action.cpu_weight is None:
            raise r.error("action", "throttle needs memory_high or cpu_weight")
    elif kind == "freeze":
        action = Freeze(
            duration=duration(), release_below=r.get("release_below", _float_in(0, 100), None)
        )
    elif kind == "backup_reload":
        action = BackupReload(paths=r.get("paths", _abs_paths, ()))
    else:
        action = Notify()
    r.finish()
    return action


def _policy(
    r: _Reader,
    limits: LimitsConfig,
    protected: tuple[str, ...],
    seen: dict[str, Path],
    avc_burst: int,
) -> Policy:
    name = r.require("name", _str)
    if name in seen:
        raise r.error(
            "name", f"duplicate policy name {name!r} (first defined in {seen[name].name})"
        )
    seen[name] = r.file
    mode: Mode = r.get("mode", _mode, "dry-run")
    cooldown = r.get("cooldown", _duration, 300.0)
    when_reader = r.sub("when")
    if when_reader is None:
        raise r.error("when", "is required")
    when = _when(when_reader, protected, avc_burst)
    actions = tuple(_action(a, limits) for a in r.tables("do"))
    if not actions:
        raise r.error("do", "needs at least one action")
    r.finish()
    return Policy(name, mode, cooldown, when, actions, r.file)


def _toml(file: Path) -> dict[str, Any]:
    try:
        with file.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(file, "(file)", f"cannot read: {e}") from None


def load_config(main: Path, policies_dir: Path) -> Config:
    root = _Reader(_toml(main), main)
    daemon, limits = _daemon(root), _limits(root)
    pr = _section(root, "protection")
    protection = ProtectionConfig(
        protected=pr.get("protected", _strs, _NO_STRS),
        allow_slices=pr.get("allow_slices", _bool, False),
    )
    pr.finish()
    correlation, redaction = _correlation(root), _redaction(root)
    sinks, metrics, control = _sinks(root, daemon.state_dir), _metrics(root), _control(root)
    root.finish("section")

    policies: list[Policy] = []
    seen: dict[str, Path] = {}
    files = sorted(policies_dir.glob("*.toml")) if policies_dir.is_dir() else []
    for file in files:
        fr = _Reader(_toml(file), file)
        policies.extend(
            _policy(t, limits, protection.protected, seen, correlation.avc_burst)
            for t in fr.tables("policy")
        )
        fr.finish("section")
    return Config(
        daemon, limits, protection, correlation, redaction, sinks, metrics, control, tuple(policies)
    )


def default_config() -> Config:
    """Every default, no policies: what an empty configuration file means."""
    return load_config(Path(os.devnull), Path(os.devnull))
