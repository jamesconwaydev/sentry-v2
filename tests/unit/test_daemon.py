import asyncio
import dataclasses
import json
import logging
import os
import shutil
import signal
import socket
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from contracts import NGINX
from sentry_v2 import __version__, actions, commands, daemon
from sentry_v2.cgroupfs import CgroupFS
from sentry_v2.collectors.audit import parse_audit_text
from sentry_v2.control import CommandError
from sentry_v2.daemon import Daemon, JournalFormatter, main, sd_notify
from sentry_v2.events import PsiEvent
from sentry_v2.state import ActionJournal, ActionRecord
from sentry_v2.systemd import UNSET, FakeSystemd

FIXTURES = Path(__file__).parent.parent / "fixtures" / "config"
S = 1_000_000

PSI_POLICY = """
[[policy]]
name = "nginx-memory"
mode = "enforce"

[policy.when]
signal = "psi"
resource = "memory"
threshold = "200ms/2s"
sustained = "0s"
cgroups = ["system.slice/nginx.service"]

[[policy.do]]
action = "throttle"
memory_high = "512M"
duration = "5m"
"""


def now_us() -> int:
    return time.time_ns() // 1000


class FakeReader:
    """Enough of systemd.journal.Reader for the collector and unit_tail."""

    def __init__(self, entries: list[dict[str, Any]], history: list[dict[str, Any]]) -> None:
        self.entries, self.history = entries, list(history)
        self.sock, self.peer = socket.socketpair()

    def fileno(self) -> int:
        return self.sock.fileno()

    def process(self) -> None:
        pass

    def get_next(self) -> dict[str, Any]:
        return self.entries.pop(0) if self.entries else {}

    def get_previous(self) -> dict[str, Any]:
        return self.history.pop() if self.history else {}

    def seek_tail(self) -> None:
        pass

    def add_match(self, **kw: str) -> None:
        pass

    def add_disjunction(self) -> None:
        pass

    def this_boot(self) -> None:
        pass

    def close(self) -> None:
        self.sock.close()
        self.peer.close()


class FakeSource:
    name = "fake"

    def __init__(self, records: list[Any]) -> None:
        self._records = records

    async def records(self):  # type: ignore[no-untyped-def]
        for r in self._records:
            yield r
        await asyncio.Event().wait()

    def close(self) -> None:
        pass


def failure_entry(unit: str, ts_us: int) -> dict[str, Any]:
    return {
        "__REALTIME_TIMESTAMP": ts_us,
        "MESSAGE_ID": "d9b373ed55a64feb8242e02dbe79a49c",
        "_PID": "1",
        "UNIT": unit,
        "UNIT_RESULT": "exit-code",
        "INVOCATION_ID": "abc",
    }


def avc_records(ts_us: int, pid: int = 77) -> list[Any]:
    stamp = f"audit({ts_us // S}.{ts_us % S // 1000:03d}:4242): "
    body = (
        f'avc:  denied  {{ read }} for  pid={pid} comm="nginx" name="shadow" '
        "scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 "
        "tclass=file permissive=0"
    )
    return [parse_audit_text("AVC", stamp + body), parse_audit_text("EOE", stamp)]


@dataclasses.dataclass
class Env:
    root: Path
    config: Path
    policies: Path
    state: Path
    sock: Path
    fs: CgroupFS
    mgr: FakeSystemd
    notes: list[str]
    journal_entries: list[dict[str, Any]]
    audit_records: list[Any]

    def write_config(self, extra: str = "") -> None:
        self.config.write_text(
            f'[daemon]\nstate_dir = "{self.state}"\n{extra}\n'
            '[correlation]\nafter = "100ms"\n'
            f'[control]\nsocket = "{self.sock}"\n'
            'group = "sv2-test-nonexistent"\nadmin_group = "sv2-test-nonexistent-admin"\n'
        )

    def daemon(self, **kw: Any) -> Daemon:
        entries = self.journal_entries
        once = {"done": False}

        def reader() -> FakeReader:
            # the first reader is the collector's; later ones serve unit_tail
            if once["done"]:
                return FakeReader([], [{"MESSAGE": "boom token=hunter2", "PRIORITY": "3"}])
            once["done"] = True
            return FakeReader(entries, [])

        kw.setdefault("audit_source_factory", lambda: FakeSource(self.audit_records))
        return Daemon(
            (self.config, self.policies),
            fs=self.fs,
            mgr_factory=lambda: self.mgr,
            journal_reader_factory=reader,
            clock=time.time,
            notify=self.notes.append,
            **kw,
        )

    def bundles(self) -> list[dict[str, Any]]:
        return [json.loads(p.read_text()) for p in sorted(self.state.glob("bundles/*/*/*/*.json"))]


@pytest.fixture
def env(fake_cgroupfs: Path) -> Iterator[Env]:
    short = Path(tempfile.mkdtemp(prefix="sv2-"))  # AF_UNIX path length limit
    policies = fake_cgroupfs / "policies.d"
    policies.mkdir()
    e = Env(
        root=fake_cgroupfs,
        config=fake_cgroupfs / "sentry-v2.toml",
        policies=policies,
        state=fake_cgroupfs / "state",
        sock=short / "control.sock",
        fs=CgroupFS(fake_cgroupfs / "cgroup", fake_cgroupfs / "proc"),
        mgr=FakeSystemd(units={"nginx.service": NGINX}),
        notes=[],
        journal_entries=[],
        audit_records=[],
    )
    e.write_config()
    yield e
    shutil.rmtree(short)


async def wait_for(cond: Callable[[], Any], timeout: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout
    while not (value := cond()):
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)
    return value


async def call(sock: Path, cmd: str, **args: Any) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(sock), limit=1 << 22)
    try:
        writer.write(json.dumps({"id": 1, "cmd": cmd, "args": args}).encode() + b"\n")
        return json.loads(await reader.readline())  # type: ignore[no-any-return]
    finally:
        writer.close()


def drive(d: Daemon, body: Callable[[], Awaitable[None]], stop: bool = True) -> None:
    async def main() -> None:
        task = asyncio.create_task(d.run())
        await asyncio.wait_for(d.ready.wait(), 5)
        try:
            await body()
        finally:
            if stop:
                d.stop()
            await asyncio.wait_for(task, 10)

    asyncio.run(main())


# -- end to end ------------------------------------------------------------


def test_unit_failure_with_avc_from_its_cgroup_makes_one_bundle(env: Env) -> None:
    ts = now_us()
    env.journal_entries.append(failure_entry("nginx.service", ts))
    env.audit_records.extend(avc_records(ts - 200_000))
    port = free_port()
    env.write_config(f"[metrics]\nenabled = true\nport = {port}\n")
    d = env.daemon()

    async def body() -> None:
        await wait_for(env.bundles)
        await asyncio.sleep(0.3)  # anything else would have arrived by now
        listing = (await call(env.sock, "incidents"))["result"]["incidents"]
        assert [i["kind"] for i in listing] == ["unit_failed"]
        shown = await call(env.sock, "show", id=listing[0]["id"])
        assert shown["result"]["bundle"]["id"] == listing[0]["id"]
        text = await scrape(port)
        assert 'sentry_v2_incidents_total{kind="unit_failed"} 1.0' in text
        assert "sentry_v2_avc_correlated_total 1.0" in text
        assert "sentry_v2_actions_active 0.0" in text

    drive(d, body)
    (bundle,) = env.bundles()
    assert bundle["incident"]["target"] == "nginx.service"
    (corr,) = bundle["correlations"]
    assert corr["avc"]["pid"] == 77 and "pid in unit cgroup" in corr["reasons"]
    assert bundle["context"]["unit"]["exec_start"] == ["/usr/sbin/nginx"]
    assert bundle["context"]["journal"][0]["message"] == "boom [REDACTED]"
    assert "system.slice/nginx.service" in bundle["context"]["psi"]
    assert "system.slice" not in bundle["context"]["psi"]  # no pressure files there
    assert env.notes[0] == "READY=1"
    assert env.notes[1].startswith("STATUS=")
    assert env.notes[-1] == "STOPPING=1"


def test_enforced_psi_throttle_is_rolled_back_on_sigterm(env: Env) -> None:
    env.write_config('mode = "enforce"')
    (env.policies / "10-psi.toml").write_text(PSI_POLICY)
    (env.root / "proc" / "pressure" / "memory").unlink()  # PSI collector: disabled
    d = env.daemon()

    async def body() -> None:
        d.queue.put_nowait(
            PsiEvent(
                ts_us=now_us(),
                cgroup="system.slice/nginx.service",
                resource="memory",
                kind="some",
                avg10=40.0,
                avg60=1.0,
                avg300=0.0,
                total_us=1,
                triggered=True,
                stall_us=200_000,
                window_us=2_000_000,
            )
        )
        await wait_for(lambda: ("set_properties", "nginx.service", str(512 * 1024**2), "None")
                       in env.mgr.calls)  # fmt: skip
        status = (await call(env.sock, "status"))["result"]
        (active,) = status["active_actions"]
        assert (active["action"], active["status"], active["mode"]) == (
            "throttle", "applied", "enforce",
        )  # fmt: skip
        assert status["collectors"]["psi"]["state"] == "disabled"
        assert status["mode"] == "enforce"
        await asyncio.sleep(0.1)
        assert status["collectors"]["psi"]["restarts"] == 0
        os.kill(os.getpid(), signal.SIGTERM)

    drive(d, body, stop=False)
    assert env.mgr.calls[-1] == ("set_properties", "nginx.service", str(UNSET), "None")
    assert env.mgr.units["nginx.service"].memory_high == UNSET
    last = ActionJournal(env.state / "state" / "actions.jsonl").load()
    assert [r.status for r in last.values()] == ["rolled_back"]
    assert env.notes[-1] == "STOPPING=1"


def test_sighup_with_broken_policy_keeps_the_old_ones(env: Env) -> None:
    shutil.copy(FIXTURES / "policies.d" / "10-ok.toml", env.policies)
    d = env.daemon()

    async def body() -> None:
        bad = env.policies / "20-bad.toml"
        bad.write_text('[[policy]]\nname = "bad"\nmode = "sometimes"\n')
        os.kill(os.getpid(), signal.SIGHUP)
        await wait_for(lambda: d.last_reload_error)
        status = await d.commands.status({})
        assert "policy[0].mode" in status["last_reload_error"]
        assert "20-bad.toml" in status["last_reload_error"]
        r = (await call(env.sock, "status"))["result"]
        assert "policy[0].mode" in r["last_reload_error"]
        listed = (await call(env.sock, "policies"))["result"]
        assert [p["name"] for p in listed["policies"]] == ["memory-hog", "crashloop", "denials"]
        assert listed["last_reload_error"] == r["last_reload_error"]
        r = await call(env.sock, "reload")
        assert r["ok"] is False and "policy[0].mode" in r["error"]

        bad.unlink()
        env.write_config('mode = "enforce"')
        assert (await call(env.sock, "reload"))["result"] == {"reloaded": True}
        assert d.last_reload_error is None
        reloads = [
            i for i, n in enumerate(env.notes) if n.startswith("RELOADING=1\nMONOTONIC_USEC=")
        ]
        assert len(reloads) == 3  # SIGHUP, the failed and the good reload command
        assert all(env.notes[i + 1] == "READY=1" for i in reloads)
        assert d.executor.mode == "enforce"
        listed = (await call(env.sock, "policies"))["result"]["policies"]
        assert listed[0] == {
            "name": "memory-hog", "mode": "enforce", "effective_mode": "enforce",
            "signal": "psi", "actions": ["throttle", "notify"],
            "source": str(env.policies / "10-ok.toml"),
        }  # fmt: skip
        assert listed[1]["effective_mode"] == "dry-run"

    drive(d, body)


def test_crashing_collector_is_restarted_with_backoff(env: Env) -> None:
    attempts: list[float] = []

    def source() -> FakeSource:
        attempts.append(time.monotonic())
        if len(attempts) < 3:
            raise OSError("netlink refused")
        return FakeSource([])

    d = env.daemon(audit_source_factory=source, backoff=(0.05, 0.08))

    async def body() -> None:
        await wait_for(lambda: len(attempts) >= 3)
        health = d.collector_health()["audit"]
        assert health["restarts"] == 2
        assert health["last_error"] == "OSError: netlink refused"
        assert health["source"] == "fake"
        assert attempts[1] - attempts[0] >= 0.05
        assert attempts[2] - attempts[1] >= 0.08  # doubled, capped at the maximum

    drive(d, body)


def test_slow_replay_keeps_extending_the_start_timeout(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "EXTEND_EVERY", 0.05)
    d = env.daemon()

    async def slow_replay() -> None:
        await asyncio.sleep(0.3)

    monkeypatch.setattr(d.executor, "replay", slow_replay)

    async def body() -> None:
        await asyncio.sleep(0.2)  # long enough for more pings, had they not stopped

    drive(d, body)
    ready = env.notes.index("READY=1")
    assert env.notes[:ready].count(daemon.EXTEND_TIMEOUT) >= 3
    assert daemon.EXTEND_TIMEOUT not in env.notes[ready:]


def test_replay_runs_before_collectors_start(env: Env) -> None:
    order: list[str] = []
    frozen = dataclasses.replace(NGINX, freezer_state="frozen")

    class Recording(FakeSystemd):
        async def thaw(self, unit: str) -> None:
            order.append("thaw")
            await super().thaw(unit)

    env.mgr = Recording(units={"nginx.service": frozen})
    journal = ActionJournal(env.state / "state" / "actions.jsonl")
    journal.append(
        ActionRecord(
            id="r1",
            policy="p",
            action="freeze",
            target="nginx.service",
            mode="enforce",
            status="applied",
            previous={"freezer_state": "running"},
            applied_at=1.0,
            expires_at=2.0,
            error=None,
            incident_id="i1",
        )
    )

    def source() -> FakeSource:
        order.append("audit")
        return FakeSource([])

    d = env.daemon(audit_source_factory=source)

    async def body() -> None:
        await wait_for(lambda: "audit" in order)
        recent = (await call(env.sock, "actions"))["result"]["recent"]
        assert recent[0]["id"] == "r1" and recent[0]["status"] == "rolled_back"
        assert isinstance(recent[0]["ts"], float)

    drive(d, body)
    assert order == ["thaw", "audit"]


def test_watchdog_pings_from_the_loop(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WATCHDOG_USEC", "40000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))
    d = env.daemon()

    async def body() -> None:
        await wait_for(lambda: env.notes.count("WATCHDOG=1") >= 3)

    drive(d, body)


def test_watchdog_for_another_pid_is_ignored(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WATCHDOG_USEC", "40000")
    monkeypatch.setenv("WATCHDOG_PID", "1")
    d = env.daemon()

    async def body() -> None:
        await asyncio.sleep(0.1)

    drive(d, body)
    assert "WATCHDOG=1" not in env.notes


def test_startup_with_bad_config_raises(env: Env) -> None:
    (env.policies / "10-bad.toml").write_text('[[policy]]\nname = "x"\nmode = "no"\n')
    with pytest.raises(daemon.ConfigError, match=r"policy\[0\]\.mode"):
        env.daemon()


# -- commands --------------------------------------------------------------


def make_record(**kw: Any) -> ActionRecord:
    fields: dict[str, Any] = dict(
        id="r1", policy="p", action="throttle", target="nginx.service", mode="enforce",
        status="applied", previous={"memory_high": UNSET}, applied_at=1.0, expires_at=2.0,
        error=None, incident_id="i1", params={"memory_high": 1, "cpu_weight": None},
    )  # fmt: skip
    fields.update(kw)
    return ActionRecord(**fields)


def test_pause_resume_rollback_and_psi(env: Env) -> None:
    d = env.daemon()
    cmd = d.commands

    async def body() -> None:
        assert await cmd.pause({}) == {"paused": True}
        assert (await cmd.status({}))["paused"] is True
        assert await cmd.resume({}) == {"paused": False}
        with pytest.raises(CommandError, match="no such action"):
            await cmd.rollback({"id": "nope"})
        with pytest.raises(CommandError, match="give id or all"):
            await cmd.rollback({})
        with pytest.raises(CommandError, match="id must be a string"):
            await cmd.rollback({"id": 3})
        assert await cmd.rollback({"all": True}) == {"rolled_back": []}

        sample = PsiEvent(
            ts_us=now_us(), cgroup="system.slice", resource="io", kind="some",
            avg10=1.5, avg60=1.0, avg300=0.5, total_us=9, triggered=False,
        )  # fmt: skip
        d.queue.put_nowait(sample)
        await wait_for(lambda: d.samples)
        assert await cmd.psi({}) == {
            "cgroups": [{"cgroup": "system.slice", "resource": "io", "kind": "some",
                         "avg10": 1.5, "avg60": 1.0, "avg300": 0.5}]
        }  # fmt: skip

    drive(d, body)


def test_samples_of_vanished_cgroups_age_out_quickly(env: Env) -> None:
    # The collector samples every live trigger every 5s, so a sample 20s old
    # belongs to a cgroup that has gone; psi and the metrics must drop it.
    d = env.daemon()

    def sample(cgroup: str, age_s: float) -> PsiEvent:
        return PsiEvent(
            ts_us=now_us() - int(age_s * 1_000_000), cgroup=cgroup, resource="cpu",
            kind="some", avg10=40.0, avg60=20.0, avg300=5.0, total_us=1, triggered=False,
        )  # fmt: skip

    async def body() -> None:
        d.samples[("gone.service", "cpu", "some")] = sample("gone.service", 20)
        d.samples[("live.service", "cpu", "some")] = sample("live.service", 1)
        await wait_for(lambda: ("gone.service", "cpu", "some") not in d.samples)
        assert [r["cgroup"] for r in (await d.commands.psi({}))["cgroups"]] == ["live.service"]

    drive(d, body)


def test_rollback_by_id(env: Env) -> None:
    env.mgr.units["nginx.service"] = dataclasses.replace(NGINX, memory_high=1)
    d = env.daemon()

    async def body() -> None:
        d.executor._active["r1"] = make_record()
        (rec,) = (await d.commands.rollback({"id": "r1"}))["rolled_back"]
        assert (rec["id"], rec["status"]) == ("r1", "rolled_back")
        assert "ts" in rec

    drive(d, body)


def test_incidents_filters_and_show_errors(env: Env) -> None:
    d = env.daemon()
    cmd = d.commands
    for i, (ts, target) in enumerate(
        [("2026-10-14T10:00:00Z", "a.service"), ("2026-10-14T11:00:00Z", "system.slice/b.service")]
    ):
        d.incidents.appendleft(
            {"id": str(i), "ts": ts, "severity": "info", "kind": "psi", "target": target,
             "policy": None}
        )  # fmt: skip

    async def body() -> None:
        ids = lambda r: [i["id"] for i in r["incidents"]]  # noqa: E731
        assert ids(await cmd.incidents({})) == ["1", "0"]
        assert ids(await cmd.incidents({"limit": 1})) == ["1"]
        assert ids(await cmd.incidents({"unit": "b.service"})) == ["1"]
        assert ids(await cmd.incidents({"since": "2026-10-14T10:30:00+00:00"})) == ["1"]
        assert ids(await cmd.incidents({"since": "2026-10-14T10:30:00"})) == ["1"]  # naive: UTC
        for bad, msg in (
            ({"since": "yesterday"}, "since must be"),
            ({"limit": 0}, "limit must be"),
            ({"limit": True}, "limit must be"),
            ({"unit": 5}, "unit must be"),
        ):
            with pytest.raises(CommandError, match=msg):
                await cmd.incidents(bad)
        with pytest.raises(CommandError, match="id must be a UUID"):
            await cmd.show({"id": "../../etc/passwd"})
        with pytest.raises(CommandError, match="no such bundle"):
            await cmd.show({"id": "0199e2c4-0000-7000-8000-000000000000"})
        with pytest.raises(CommandError, match="id is required"):
            await cmd.show({})

    drive(d, body)


@pytest.fixture
def unit_roots(env: Env, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Stands in for /etc/systemd/system, the one tree restore may write."""
    etc = env.root / "etc"
    monkeypatch.setattr(commands, "RESTORE_ROOTS", (etc,))
    return etc


def test_restore(env: Env, unit_roots: Path) -> None:
    unit_file = env.root / "etc" / "demo.service"
    unit_file.parent.mkdir()
    unit_file.write_text("[Service]\nExecStart=/bin/true\n")
    d = env.daemon()
    backups = d.executor.backups_dir
    backup_id = actions.backup("demo.service", [str(unit_file)], backups, 1_800_000_000.0)
    unit_file.write_text("broken")
    cmd = d.commands

    async def body() -> None:
        r = await cmd.restore({"backup_id": backup_id})
        assert r == {
            "restored": [str(unit_file)],
            "skipped": [],
            "note": "run systemctl daemon-reload && systemctl reload demo.service",
        }
        assert unit_file.read_text() == "[Service]\nExecStart=/bin/true\n"

        for bad in ("../x/20270115T080000Z", "demo.service/latest", "a/b/20270115T080000Z",
                    "../20270115T080000Z"):  # fmt: skip
            with pytest.raises(CommandError, match="backup_id must look like"):
                await cmd.restore({"backup_id": bad})
        with pytest.raises(CommandError, match="no such backup"):
            await cmd.restore({"backup_id": "demo.service/20000101T000000Z"})

        (backups / "demo.service").chmod(0o770)
        with pytest.raises(CommandError, match="writable only by it"):
            await cmd.restore({"backup_id": backup_id})
        (backups / "demo.service").chmod(0o700)

        copy = backups / backup_id / "files" / str(unit_file).lstrip("/")
        copy.write_text("tampered")
        with pytest.raises(CommandError, match="checksum mismatch"):
            await cmd.restore({"backup_id": backup_id})
        assert unit_file.read_text() == "[Service]\nExecStart=/bin/true\n"  # untouched

        (backups / backup_id / "MANIFEST.sha256").write_text("abc  files/../../../etc/passwd\n")
        with pytest.raises(CommandError, match="manifest is malformed"):
            await cmd.restore({"backup_id": backup_id})

    drive(d, body)


def test_restore_does_not_copy_the_backups_label(
    env: Env, unit_roots: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # copystat would stamp the backup's SELinux label on the restored unit
    # file, and the daemon's domain may not relabel files anyway
    def denied(*_a: object, **_k: object) -> None:
        raise PermissionError(13, "Permission denied", "security.selinux")

    unit_file = env.root / "etc" / "demo.service"
    unit_file.parent.mkdir()
    unit_file.write_text("[Service]\n")
    os.utime(unit_file, (1000, 1000))
    d = env.daemon()
    backup_id = actions.backup("demo.service", [str(unit_file)], d.executor.backups_dir, 0.0)
    unit_file.write_text("broken")
    monkeypatch.setattr(shutil, "copystat", denied)

    async def body() -> None:
        assert (await d.commands.restore({"backup_id": backup_id}))["restored"] == [str(unit_file)]
        assert unit_file.read_text() == "[Service]\n"
        assert unit_file.stat().st_mtime == 1000

    drive(d, body)


def _vendor_unit_with_drop_in(env: Env) -> tuple[Path, Path, Daemon, str]:
    """A package's unit outside the writable roots plus an admin drop-in, backed up."""
    fragment = env.root / "usr" / "demo.service"
    fragment.parent.mkdir()
    fragment.write_text("[Service]\nExecStart=/bin/true\n")
    drop_in = env.root / "etc" / "demo.service.d" / "override.conf"
    drop_in.parent.mkdir(parents=True)
    drop_in.write_text("[Service]\nNice=5\n")
    d = env.daemon()
    files = [str(fragment), str(drop_in)]
    return fragment, drop_in, d, actions.backup("demo.service", files, d.executor.backups_dir, 0.0)


def test_restore_skips_unchanged_files_outside_the_unit_dirs(env: Env, unit_roots: Path) -> None:
    fragment, drop_in, d, backup_id = _vendor_unit_with_drop_in(env)
    drop_in.write_text("broken")

    async def body() -> None:
        r = await d.commands.restore({"backup_id": backup_id})
        assert r["restored"] == [str(drop_in)]
        assert r["skipped"] == [str(fragment)]
        assert drop_in.read_text() == "[Service]\nNice=5\n"

        r = await d.commands.restore({"backup_id": backup_id})
        assert (r["restored"], r["skipped"]) == ([], [str(fragment), str(drop_in)])
        assert "nothing to do" in r["note"]

    drive(d, body)


def test_restore_refuses_changed_files_outside_the_unit_dirs(env: Env, unit_roots: Path) -> None:
    fragment, drop_in, d, backup_id = _vendor_unit_with_drop_in(env)
    fragment.write_text("vendor update")
    drop_in.write_text("broken")

    async def body() -> None:
        with pytest.raises(CommandError) as e:
            await d.commands.restore({"backup_id": backup_id})
        msg = str(e.value)
        assert msg.startswith("nothing restored")
        assert str(fragment) in msg and str(drop_in) not in msg
        assert f"{d.executor.backups_dir / backup_id}/files" in msg
        assert (fragment.read_text(), drop_in.read_text()) == ("vendor update", "broken")

    drive(d, body)


def test_restore_recreates_a_removed_drop_in_directory(env: Env, unit_roots: Path) -> None:
    _fragment, drop_in, d, backup_id = _vendor_unit_with_drop_in(env)
    shutil.rmtree(drop_in.parent)

    async def body() -> None:
        old = os.umask(0o077)  # the unit's UMask
        try:
            r = await d.commands.restore({"backup_id": backup_id})
        finally:
            os.umask(old)
        assert r["restored"] == [str(drop_in)]
        assert drop_in.read_text() == "[Service]\nNice=5\n"
        assert drop_in.parent.stat().st_mode & 0o777 == 0o755

    drive(d, body)


def test_subscribe_receives_incidents_and_records(env: Env) -> None:
    ts = now_us()
    env.journal_entries.append(failure_entry("nginx.service", ts + 300_000))
    d = env.daemon()

    async def body() -> None:
        reader, writer = await asyncio.open_unix_connection(str(env.sock), limit=1 << 22)
        writer.write(b'{"id": 1, "cmd": "subscribe"}\n')
        assert json.loads(await reader.readline())["ok"] is True
        event = json.loads(await asyncio.wait_for(reader.readline(), 5))["event"]
        assert event["type"] == "incident"
        assert event["incident"]["target"] == "nginx.service"
        writer.close()

    drive(d, body)


def test_alert_becomes_a_critical_bundle(env: Env) -> None:
    d = env.daemon()

    async def body() -> None:
        await d.reporter.alert("breaker_open", {"failures": 3, "until": 1.0})
        (bundle,) = await wait_for(env.bundles)
        assert (bundle["severity"], bundle["incident"]["alert"]) == ("critical", "breaker_open")
        assert d.incidents[0]["kind"] == "alert"

    drive(d, body)


# -- main and helpers ------------------------------------------------------


def test_check_exit_codes(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    shutil.copy(FIXTURES / "policies.d" / "10-ok.toml", env.policies)
    argv = ["--config", str(env.config), "--policies", str(env.policies), "--check"]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "3 policies" in out and "memory-hog" in out

    (env.policies / "20-bad.toml").write_text('[[policy]]\nname = "x"\nmode = "no"\n')
    assert main(argv) == 2
    assert "20-bad.toml: policy[0].mode" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_main_runs_the_daemon(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Stub:
        def __init__(self, paths: tuple[Path, Path], **kw: Any) -> None:
            seen["paths"], seen["kw"] = paths, kw
            self.cfg = daemon.load_config(*paths)

        async def run(self) -> None:
            seen["ran"] = True

    monkeypatch.setattr(daemon, "Daemon", Stub)
    assert main(["--config", str(env.config), "--policies", str(env.policies)]) == 0
    assert seen["ran"] and seen["paths"] == (env.config, env.policies)
    assert set(seen["kw"]) >= {"fs", "mgr_factory", "journal_reader_factory"}


def test_main_reports_config_errors(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.config.write_text("[daemon]\nmode = 1\n")
    assert main(["--config", str(env.config), "--policies", str(env.policies)]) == 2
    assert "daemon.mode" in capsys.readouterr().err


def test_journal_formatter_prefixes_priority() -> None:
    f = JournalFormatter("%(message)s")
    rec = logging.LogRecord("sentry_v2.x", logging.WARNING, "f", 1, "hi %s", ("there",), None)
    assert f.format(rec) == "<4>sentry_v2.x: hi there"
    rec.levelno = logging.CRITICAL
    assert f.format(rec).startswith("<2>")


def test_sd_notify_without_systemd_is_a_no_op() -> None:
    sd_notify("READY=1")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def scrape(port: int) -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
    data = await reader.read()
    writer.close()
    return data.decode()


FREEZE_POLICY = """
[[policy]]
name = "nginx-freeze"
mode = "enforce"

[policy.when]
signal = "unit_failed"
units = ["nginx.service"]

[[policy.do]]
action = "freeze"
duration = "2m"
"""


def test_freeze_is_thawed_on_sigterm_and_a_second_sigterm_is_ignored(env: Env) -> None:
    env.write_config('mode = "enforce"')
    (env.policies / "10-freeze.toml").write_text(FREEZE_POLICY)
    env.journal_entries.append(failure_entry("nginx.service", now_us()))
    thawing = asyncio.Event()
    release = asyncio.Event()

    class SlowThaw(FakeSystemd):
        async def thaw(self, unit: str) -> None:
            thawing.set()
            await release.wait()
            await super().thaw(unit)

    env.mgr = SlowThaw(units={"nginx.service": NGINX})
    d = env.daemon()

    async def body() -> None:
        await wait_for(lambda: env.mgr.units["nginx.service"].freezer_state == "frozen")
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(thawing.wait(), 5)
        os.kill(os.getpid(), signal.SIGTERM)  # mid-rollback: logged and ignored
        os.kill(os.getpid(), signal.SIGHUP)  # stopping: no reload
        await asyncio.sleep(0.05)
        release.set()

    drive(d, body, stop=False)
    assert env.mgr.units["nginx.service"].freezer_state == "running"
    assert not any(n.startswith("RELOADING=1") for n in env.notes)
    (rec,) = ActionJournal(env.state / "state" / "actions.jsonl").load().values()
    assert (rec.action, rec.status) == ("freeze", "rolled_back")


def test_sighup_before_ready_is_ignored(env: Env) -> None:
    d = env.daemon()
    d._on_sighup()
    assert not d._tasks


def test_reload_survives_unexpected_errors_and_keeps_restart_counts(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = env.daemon()

    async def body() -> None:
        d._health["psi"]["restarts"] = 4
        monkeypatch.setattr(d, "_apply", lambda cfg, redactor: 1 / 0)
        err = await d.reload()
        assert err == "ZeroDivisionError: division by zero"
        assert d.last_reload_error == err
        monkeypatch.undo()
        assert await d.reload() is None
        await wait_for(lambda: "psi" in d._collectors)
        assert d.collector_health()["psi"]["restarts"] == 4

    drive(d, body)


def test_broken_health_and_stale_psi_collector(env: Env) -> None:
    d = env.daemon()

    class Broken:
        async def run(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            raise RuntimeError("nope")

    async def body() -> None:
        d._collectors["broken"] = Broken()  # type: ignore[assignment]
        d._health["broken"] = {"restarts": 0, "last_error": None}
        assert d.collector_health()["broken"]["state"] == "unknown"
        psi = d._psi
        assert psi is not None
        d._collector_tasks["psi"].cancel()
        await wait_for(lambda: d._psi is None)
        d._units_changed()  # no collector: nothing to hint

    drive(d, body)


def test_failed_spawned_task_is_logged(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    d = env.daemon()

    async def boom() -> None:
        raise RuntimeError("kaput")

    async def body() -> None:
        d._spawn(boom(), "boom")
        await wait_for(lambda: "task boom failed" in caplog.text)

    drive(d, body)


def test_failed_reload_leaves_running_state_untouched(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    shutil.copy(FIXTURES / "policies.d" / "10-ok.toml", env.policies)
    built: list[object] = []

    def sinks(cfg: Any) -> list[Any]:
        built.append(cfg)
        if len(built) > 1:
            raise RuntimeError("sink exploded")
        return daemon.build_sinks(cfg.sinks, cfg.daemon.state_dir)

    d = env.daemon(sinks_factory=sinks)

    async def body() -> None:
        before = (d.cfg, d.sinks, d.reporter.redactor, d.executor.mode, d.executor.limits)
        env.write_config('mode = "enforce"')  # valid, so only the sinks can fail
        assert await d.reload() == "RuntimeError: sink exploded"
        after = (d.cfg, d.sinks, d.reporter.redactor, d.executor.mode, d.executor.limits)
        assert after == before and d.executor.mode == "dry-run"

        def bad_redactor(cfg: Any) -> Any:
            raise ValueError("bad pattern")

        monkeypatch.setattr(daemon.Redactor, "from_config", bad_redactor)
        assert await d.reload() == "ValueError: bad pattern"
        assert len(built) == 2  # failed before the sinks were even built
        assert (d.cfg, d.sinks, d.reporter.redactor) == before[:3]

    drive(d, body)
