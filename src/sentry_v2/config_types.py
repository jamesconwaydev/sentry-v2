"""Frozen section dataclasses for the global configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .policy import Mode, Policy
from .units import parse_duration


@dataclass(frozen=True)
class DaemonConfig:
    """Daemon settings.

    `mode` is a master switch. An action is enforced only when `daemon.mode`
    and the policy's own `mode` are both "enforce"; otherwise it is dry-run.
    """

    log_level: str = "info"
    state_dir: Path = Path("/var/lib/sentry-v2")
    queue_size: int = 10000
    mode: Mode = "dry-run"


@dataclass(frozen=True)
class LimitsConfig:
    max_active_actions: int = 5
    max_concurrent_freezes: int = 1
    max_action_duration: float = 1800.0
    breaker_failures: int = 3
    breaker_window: float = 600.0
    breaker_cooldown: float = 900.0


@dataclass(frozen=True)
class ProtectionConfig:
    protected: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationConfig:
    retention: float = 60.0
    before: float = 5.0
    after: float = 1.0
    min_confidence: float = 0.5
    avc_burst: int = 5


@dataclass(frozen=True)
class RedactionConfig:
    patterns: tuple[str, ...] = ()
    use_defaults: bool = True


@dataclass(frozen=True)
class FileSinkConfig:
    dir: Path = Path("/var/lib/sentry-v2/bundles")
    max_age: float = parse_duration("30d")
    max_size: int = 1024**3


@dataclass(frozen=True)
class WebhookSinkConfig:
    url: str
    hmac_key_file: Path | None = None
    ca_file: Path | None = None
    timeout: float = 10.0


@dataclass(frozen=True)
class SyslogSinkConfig:
    host: str = "127.0.0.1"
    port: int = 514
    transport: Literal["udp", "tcp", "tls"] = "udp"
    ca_file: Path | None = None


@dataclass(frozen=True)
class SplunkHecSinkConfig:
    url: str
    token_file: Path
    index: str | None = None
    ca_file: Path | None = None


@dataclass(frozen=True)
class ElasticSinkConfig:
    url: str
    index: str
    api_key_file: Path | None = None
    username: str | None = None
    password_file: Path | None = None
    ca_file: Path | None = None


@dataclass(frozen=True)
class SinksConfig:
    file: FileSinkConfig = field(default_factory=FileSinkConfig)
    webhook: WebhookSinkConfig | None = None
    syslog: SyslogSinkConfig | None = None
    splunk_hec: SplunkHecSinkConfig | None = None
    elastic: ElasticSinkConfig | None = None


@dataclass(frozen=True)
class MetricsConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 9787


@dataclass(frozen=True)
class ControlConfig:
    socket: Path = Path("/run/sentry-v2/control.sock")
    group: str = "sentry-v2"
    admin_group: str = "sentry-v2-admin"


@dataclass(frozen=True)
class Config:
    daemon: DaemonConfig
    limits: LimitsConfig
    protection: ProtectionConfig
    correlation: CorrelationConfig
    redaction: RedactionConfig
    sinks: SinksConfig
    metrics: MetricsConfig
    control: ControlConfig
    policies: tuple[Policy, ...]
