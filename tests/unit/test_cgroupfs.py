from pathlib import Path

from sentry_v2.cgroupfs import CgroupFS, parse_pressure
from sentry_v2.events import PressureLine


def make(base: Path) -> CgroupFS:
    return CgroupFS(base / "cgroup", base / "proc")


def test_parse_pressure_exact() -> None:
    got = parse_pressure(
        "some avg10=1.50 avg60=0.20 avg300=0.00 total=12345\n"
        "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
    )
    assert got == {
        "some": PressureLine(1.5, 0.2, 0.0, 12345),
        "full": PressureLine(0.0, 0.0, 0.0, 0),
    }


def test_parse_pressure_some_only() -> None:
    assert list(parse_pressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n")) == ["some"]


def test_psi_available(fake_cgroupfs: Path) -> None:
    assert make(fake_cgroupfs).psi_available()
    assert not CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "nope").psi_available()


def test_glob(fake_cgroupfs: Path) -> None:
    fs = make(fake_cgroupfs)
    assert fs.glob(["system.slice/batch-*.service"]) == [
        "system.slice/batch-1.service",
        "system.slice/batch-2.service",
    ]
    assert fs.glob(["nginx.service"]) == ["system.slice/nginx.service"]
    assert fs.glob(["missing.service"]) == []


def test_reads(fake_cgroupfs: Path) -> None:
    fs = make(fake_cgroupfs)
    assert fs.read_pressure("system.slice/nginx.service", "memory")["some"].avg10 == 42.0
    assert fs.memory_current("system.slice/nginx.service") == 4096


def test_pid_cgroup(fake_cgroupfs: Path) -> None:
    fs = make(fake_cgroupfs)
    assert fs.pid_cgroup(77) == "system.slice/nginx.service"
    assert fs.pid_cgroup(1234) is None


def test_pid_cgroup_without_v2_line(fake_cgroupfs: Path) -> None:
    (fake_cgroupfs / "proc" / "77" / "cgroup").write_text("1:name=systemd:/x\n")
    assert make(fake_cgroupfs).pid_cgroup(77) is None


def test_unit_of() -> None:
    fs = CgroupFS()
    assert fs.unit_of("system.slice/nginx.service") == "nginx.service"
    assert fs.unit_of("user.slice/session-1.scope") == "session-1.scope"
    assert fs.unit_of("system.slice/foo") is None
    assert fs.unit_of("") is None


def test_open_trigger_writes_spec(fake_cgroupfs: Path) -> None:
    import os

    fs = make(fake_cgroupfs)
    fd = fs.open_trigger("system.slice/nginx.service", "memory", "some", 150000, 1000000)
    os.close(fd)
    text = (fake_cgroupfs / "cgroup/system.slice/nginx.service/memory.pressure").read_bytes()
    assert text.startswith(b"some 150000 1000000\0")
