import configparser
import re
from pathlib import Path

import sentry_v2
from sentry_v2.config import load_config

ROOT = Path(__file__).parents[2]
PACKAGING = ROOT / "packaging"
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
        "Type": "notify-reload",
        "NotifyAccess": "main",
        "WatchdogSec": "30s",
        "Restart": "on-failure",
        "RestartPreventExitStatus": "2",
        "ExecStart": "/usr/bin/sentry-v2",
        "TimeoutStopSec": "780s",
        "TimeoutStartSec": "780s",
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "SystemCallFilter": "@system-service",
        "RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_INET AF_INET6",
        "CapabilityBoundingSet": "CAP_AUDIT_READ",
        "StateDirectoryMode": "0700",
        "RuntimeDirectoryMode": "0750",
        "MemoryMax": "192M",
        "OOMScoreAdjust": "-900",
    }
    assert {k: svc.get(k) for k in expected} == expected
    assert "ExecReload" not in svc  # notify-reload sends SIGHUP itself
    assert set(svc["ReadWritePaths"].split()) == {
        "/var/lib/sentry-v2",
        "/sys/fs/cgroup",
        "-/etc/systemd/system",
        "-/run/systemd/system",
    }
    assert unit["Install"]["WantedBy"] == "multi-user.target"


def test_spec_version_matches_package() -> None:
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    m = re.search(r"^%global upstream_version (\S+)$", spec, re.MULTILINE)
    assert m is not None and m.group(1) == sentry_v2.__version__
    assert re.search(r"^Version:\s+%\{upstream_version\}$", spec, re.MULTILINE)


def test_selinux_module_version_matches_package() -> None:
    te = (PACKAGING / "selinux" / "sentry_v2.te").read_text()
    m = re.search(r"^policy_module\(sentry_v2, *([^)\s]+)\)$", te, re.MULTILINE)
    assert m is not None and m.group(1) == sentry_v2.__version__


def test_spec_ships_every_cockpit_file() -> None:
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    files = spec.split("%files cockpit", 1)[1].split("%changelog", 1)[0]
    install = re.search(r"^install -pm 0644 (cockpit/.*?)\\?$", spec, re.MULTILINE)
    assert install is not None
    for path in sorted((ROOT / "cockpit").iterdir()):
        assert f"cockpit/{path.name}" in install.group(1).split(), path.name
        assert f"%{{_datadir}}/cockpit/sentry-v2/{path.name}" in files, path.name
    assert " cockpit " in (ROOT / "Makefile").read_text(), (
        "the source tarball must include cockpit/"
    )


def test_spec_import_check_covers_every_module() -> None:
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    assert re.search(r"^%pyproject_check_import$", spec, re.MULTILINE)


def test_spec_installs_the_licence_where_rpm_looks() -> None:
    # /usr/share/licenses/sentry-v2/LICENSE; the subpackages require this one
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    main_files = spec.split("%files -f %{pyproject_files}", 1)[1].split("%files ", 1)[0]
    assert "%license LICENSE" in main_files
