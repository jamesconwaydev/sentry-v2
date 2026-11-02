# SPDX-FileCopyrightText: Copyright the Sentry-v2 contributors
# SPDX-License-Identifier: Apache-2.0
import argparse
import configparser
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

import sentry_v2
from sentry_v2.cli import _parser as cli_parser
from sentry_v2.config import load_config
from sentry_v2.daemon import _parser as daemon_parser

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
        "ExecStopPost": "/usr/bin/sentry-v2 --rollback-only",
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


def _options(parser: argparse.ArgumentParser, prefix: str = "") -> set[str]:
    """Every subcommand path and long option a parser accepts, help aside."""
    out: set[str] = set()
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for name, sub in a.choices.items():
                out.add(prefix + name)
                out |= _options(sub, f"{prefix}{name} ")
        else:
            out |= {o for o in a.option_strings if o.startswith("--") and o != "--help"}
    return out


@pytest.mark.parametrize(
    ("page", "parser"),
    [("sentry-v2.8", daemon_parser), ("sentry-v2ctl.8", cli_parser)],
)
def test_man_page_covers_every_command_and_option(page: str, parser: Any) -> None:
    text = (PACKAGING / "man" / page).read_text().replace("\\-", "-")
    text = re.sub(r"\\f[BIR]", "", text)
    missing = sorted(o for o in _options(parser()) if o not in text)
    assert not missing, f"{page} doesn't mention {missing}"


def test_spec_installs_the_man_pages() -> None:
    spec = (PACKAGING / "sentry-v2.spec").read_text()
    for page in ("sentry-v2.8", "sentry-v2ctl.8"):
        assert f"packaging/man/{page} %{{buildroot}}%{{_mandir}}/man8/{page}" in spec
        assert f"%{{_mandir}}/man8/{page}*" in spec


def test_source_tarball_ignores_mtimes_and_modes(tmp_path: Path) -> None:
    builds = []
    for n, (stamp, mode) in enumerate([(1_000_000_000, 0o664), (1_700_000_000, 0o644)]):
        tree = tmp_path / f"tree{n}"
        (tree / "packaging").mkdir(parents=True)
        (tree / "packaging/sentry-v2.spec").write_text((PACKAGING / "sentry-v2.spec").read_text())
        (tree / "src/pkg/__pycache__").mkdir(parents=True)
        (tree / "src/pkg/__pycache__/x.pyc").write_bytes(b"junk")
        for name in ("src/pkg/b.py", "src/pkg/a.py"):
            (tree / name).write_text("x = 1\n")
            os.chmod(tree / name, mode)
            os.utime(tree / name, (stamp, stamp))
        out = tmp_path / f"out{n}.tar.gz"
        subprocess.run(  # noqa: S603
            [sys.executable, ROOT / "scripts/source-tarball.py", out, "p-1", "src", "packaging"],
            cwd=tree,
            check=True,
        )
        builds.append(out.read_bytes())
    assert builds[0] == builds[1]
    with tarfile.open(tmp_path / "out0.tar.gz") as tar:
        names = tar.getnames()
        assert names[0] == "p-1" and tar.getmember("p-1").isdir()
        assert "p-1/src/pkg/a.py" in names
        assert not any("__pycache__" in n for n in names)
        assert {m.mtime for m in tar.getmembers()} == {m.mtime for m in tar.getmembers()[:1]}


SOURCE_GLOBS = ("src/**/*.py", "tests/**/*.py", "fuzz/*.py", "scripts/*", "cockpit/*.html")
SOURCE_GLOBS += ("cockpit/*.js", "cockpit/*.css")
SOURCE_GLOBS += ("examples/**/*.sh", "examples/**/*.te", "packaging/selinux/*.*")
SOURCE_GLOBS += (".clusterfuzzlite/*.sh", "Makefile")


def test_every_source_file_names_copyright_and_licence() -> None:
    files = {p for g in SOURCE_GLOBS for p in ROOT.glob(g) if p.is_file()}
    files = {p for p in files if "__pycache__" not in p.parts and p.suffix != ".pyc"}
    assert len(files) > 90
    missing = [
        str(p.relative_to(ROOT))
        for p in sorted(files)
        if "SPDX-FileCopyrightText: Copyright the Sentry-v2 contributors" not in p.read_text()
        or "SPDX-License-Identifier: Apache-2.0" not in p.read_text()
    ]
    assert not missing, missing
