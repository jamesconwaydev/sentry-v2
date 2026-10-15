import configparser
import re
from pathlib import Path

import sentry_v2
from sentry_v2.config import load_config

PACKAGING = Path(__file__).parents[2] / "packaging"
EXAMPLES = PACKAGING / "examples"


def test_examples_load_and_stay_in_dry_run() -> None:
    cfg = load_config(EXAMPLES / "sentry-v2.toml", EXAMPLES / "policies.d")
    assert cfg.daemon.mode == "dry-run"
    assert cfg.metrics.enabled is False
    sinks = cfg.sinks
    assert (sinks.webhook, sinks.syslog, sinks.splunk_hec, sinks.elastic) == (None,) * 4
    assert {p.name for p in cfg.policies} == {
        "memory-pressure-throttle",
        "unit-failure-notify",
        "io-pressure-freeze-batch",
    }
    assert all(p.mode == "dry-run" for p in cfg.policies)


def test_unit_file_hardening() -> None:
    unit = configparser.ConfigParser(strict=False, interpolation=None)
    unit.optionxform = str  # type: ignore[assignment,method-assign]
    unit.read(PACKAGING / "sentry-v2.service")
    svc = unit["Service"]
    expected = {
        "Type": "notify",
        "NotifyAccess": "main",
        "WatchdogSec": "30s",
        "Restart": "on-failure",
        "ExecStart": "/usr/bin/sentry-v2",
        "TimeoutStopSec": "330s",
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "SystemCallFilter": "@system-service",
        "RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_INET AF_INET6",
        "CapabilityBoundingSet": "CAP_AUDIT_READ CAP_SYS_PTRACE CAP_DAC_READ_SEARCH",
        "StateDirectoryMode": "0700",
        "RuntimeDirectoryMode": "0750",
        "MemoryMax": "192M",
        "OOMScoreAdjust": "-900",
    }
    assert {k: svc.get(k) for k in expected} == expected
    assert set(svc["ReadWritePaths"].split()) == {"/var/lib/sentry-v2", "/sys/fs/cgroup"}
    assert unit["Install"]["WantedBy"] == "multi-user.target"


def test_spec_version_matches_package() -> None:
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    m = re.search(r"^%global upstream_version (\S+)$", spec, re.MULTILINE)
    assert m is not None and m.group(1) == sentry_v2.__version__
    assert re.search(r"^Version:\s+%\{upstream_version\}$", spec, re.MULTILINE)
