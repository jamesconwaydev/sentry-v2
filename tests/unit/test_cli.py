import json
import shutil
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from sentry_v2.cli import main
from sentry_v2.client import ControlClient, ControlError, NotRunning, PermissionDenied

FIX = Path(__file__).parent.parent / "fixtures" / "config"
CFG = ["--config", str(FIX / "minimal.toml"), "--policies", str(FIX / "policies.d")]

STATUS = {
    "version": "0.1.0",
    "mode": "dry-run",
    "paused": False,
    "uptime_s": 3725,
    "collectors": {"psi": {"state": "ok"}},
    "active_actions": [
        {
            "id": "a1",
            "policy": "memory-hog",
            "action": "throttle",
            "target": "batch.service",
            "status": "applied",
            "expires_at": 4102444800.0,
        }
    ],
    "last_reload_error": "bad.toml: x: nope",
    "events_dropped": {},
}


class Stub:
    """A control server on a real Unix socket answering from a dict."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(dir="/tmp"))
        self.path = self.dir / "c.sock"
        self.replies: dict[str, dict] = {}
        self.seen: list[dict] = []
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(str(self.path))
        self.srv.listen()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c, c.makefile("rwb") as f:
                req = json.loads(f.readline())
                self.seen.append(req)
                if req["cmd"] == "subscribe":
                    f.write(b'{"id":1,"ok":true,"result":{}}\n{"event":{"a":1}}\n')
                else:
                    f.write(json.dumps({"id": req["id"], **self.replies[req["cmd"]]}).encode())
                    f.write(b"\n")
                f.flush()


@pytest.fixture
def stub():
    s = Stub()
    yield s
    s.srv.close()
    shutil.rmtree(s.dir)


def run(stub, capsys, *argv):
    rc = main(["--socket", str(stub.path), *argv])
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_status_table(stub, capsys):
    stub.replies["status"] = {"ok": True, "result": STATUS}
    rc, out, _ = run(stub, capsys, "status")
    assert rc == 0
    assert "dry-run" in out and "1h2m" in out and "memory-hog" in out and "bad.toml" in out


def test_status_json(stub, capsys):
    stub.replies["status"] = {"ok": True, "result": STATUS}
    rc, out, _ = run(stub, capsys, "status", "--json")
    assert rc == 0 and json.loads(out) == STATUS


def test_rollback_ok_and_err(stub, capsys):
    stub.replies["rollback"] = {"ok": True, "result": {"rolled_back": [{"id": "a1"}]}}
    rc, out, _ = run(stub, capsys, "rollback", "a1")
    assert rc == 0 and "a1" in out and stub.seen[-1]["args"] == {"id": "a1"}
    stub.replies["rollback"] = {"ok": False, "error": "no such action"}
    rc, _, err = run(stub, capsys, "rollback", "zz")
    assert rc == 1 and "no such action" in err
    run(stub, capsys, "rollback", "--all")
    assert stub.seen[-1]["args"] == {"all": True}


def test_simple_commands(stub, capsys):
    stub.replies |= {
        "pause": {"ok": True, "result": {"paused": True}},
        "resume": {"ok": True, "result": {"paused": False}},
        "reload": {"ok": True, "result": {"reloaded": True}},
        "restore": {"ok": True, "result": {"restored": ["/etc/x"], "note": "reload it"}},
        "psi": {
            "ok": True,
            "result": {
                "cgroups": [
                    {
                        "cgroup": "b",
                        "resource": "cpu",
                        "kind": "some",
                        "avg10": 1.0,
                        "avg60": 0,
                        "avg300": 0,
                    },
                    {
                        "cgroup": "a",
                        "resource": "cpu",
                        "kind": "some",
                        "avg10": 9.5,
                        "avg60": 0,
                        "avg300": 0,
                    },
                ]
            },
        },
        "incidents": {
            "ok": True,
            "result": {
                "incidents": [
                    {
                        "id": "i1",
                        "ts": "2020-01-01T00:00:00Z",
                        "severity": "high",
                        "kind": "psi",
                        "target": "t",
                        "policy": "p",
                    }
                ]
            },
        },
        "show": {"ok": True, "result": {"bundle": {"schema": "x"}}},
        "actions": {
            "ok": True,
            "result": {"active": [], "recent": [{"id": "r1", "status": "failed", "ts": 1.0}]},
        },
    }
    for argv, needle in [
        (["pause"], "paused"),
        (["resume"], "resumed"),
        (["reload"], "reloaded"),
        (["restore", "u.service/20260101T000000Z"], "/etc/x"),
        (["top", "--once"], "a"),
        (["incidents", "--since", "2020-01-01T00:00:00Z", "--unit", "t", "--limit", "5"], "i1"),
        (["show", "i1"], "sentry-v2".replace("sentry-v2", "schema")),
        (["actions"], "r1"),
    ]:
        rc, out, _ = run(stub, capsys, *argv)
        assert rc == 0 and needle in out, argv
    rc, out, _ = run(stub, capsys, "top", "--once", "--sort", "cgroup")
    assert out.index("\na ") < out.index("\nb ")
    assert stub.seen[-1]["cmd"] == "psi"


def test_top_loop_exits_on_ctrl_c(stub, capsys, monkeypatch):
    stub.replies["psi"] = {"ok": True, "result": {"cgroups": []}}
    monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
    monkeypatch.setattr("time.sleep", lambda _: (_ for _ in ()).throw(KeyboardInterrupt))
    assert main(["--socket", str(stub.path), "top"]) == 0
    assert "\x1b[H\x1b[2J" in capsys.readouterr().out


def test_not_running(stub, capsys):
    p = stub.dir / "nope.sock"
    rc = main(["--socket", str(p), "status"])
    assert rc == 2
    assert capsys.readouterr().err.strip() == f"sentry-v2 is not running (no socket at {p})"
    with pytest.raises(NotRunning):
        ControlClient(p).call("status")


def test_permission_denied(stub, capsys, monkeypatch):
    def deny(self, addr):
        raise PermissionError

    monkeypatch.setattr(socket.socket, "connect", deny)
    rc, _, err = run(stub, capsys, "status")
    assert rc == 3 and "sentry-v2 group" in err
    with pytest.raises(PermissionDenied):
        ControlClient(stub.path).call("status")


def test_server_side_permission_error_is_exit_3(stub, capsys):
    stub.replies["pause"] = {"ok": False, "error": "permission denied: needs sentry-v2-admin"}
    rc, _, err = run(stub, capsys, "pause")
    assert rc == 3 and "sentry-v2-admin" in err


def test_subscribe_and_call_errors(stub):
    assert list(ControlClient(stub.path).subscribe()) == [{"a": 1}]
    stub.replies["x"] = {"ok": False, "error": "boom"}
    with pytest.raises(ControlError, match="boom"):
        ControlClient(stub.path).call("x")


def test_usage_error(capsys):
    assert main(["bogus"]) == 2


def test_policy_validate_good(capsys):
    assert main(["policy", "validate", *CFG]) == 0
    assert "3 policies" in capsys.readouterr().out


def test_policy_validate_bad(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[daemon]\nmode = 'yolo'\n")
    assert main(["policy", "validate", "--config", str(bad), "--policies", str(tmp_path)]) == 1
    assert "bad.toml: daemon.mode" in capsys.readouterr().err
    assert main(["--json", "policy", "validate", "--config", str(bad)]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False


def _event(tmp_path, ev):
    f = tmp_path / "e.json"
    f.write_text(json.dumps(ev))
    return ["policy", "test", "--event", str(f), *CFG]


PSI = {
    "kind": "psi", "ts_us": 100_000_000, "cgroup": "system.slice/batch.service",
    "resource": "memory", "pressure": "full", "avg10": 40.0, "avg60": 20.0, "avg300": 5.0,
    "total_us": 1, "triggered": True, "stall_us": 150000, "window_us": 1000000,
}  # fmt: skip


def test_policy_test_psi_throttle(tmp_path, capsys):
    assert main(_event(tmp_path, PSI)) == 0
    out = capsys.readouterr().out
    assert "memory-hog" in out and "throttle" in out and "dry-run" in out
    assert "memory_high=80%" in out and "notify" in out


def test_policy_test_no_match(tmp_path, capsys):
    assert main(_event(tmp_path, {**PSI, "resource": "cpu"})) == 0
    assert "no policy matches" in capsys.readouterr().out


def test_policy_test_unit_failed_list_json(tmp_path, capsys):
    evs = [
        {"kind": "unit_failed", "ts_us": 5_000_000, "unit": "batch-1.service", "result": "watchdog"}
    ]
    assert main(["--json", *_event(tmp_path, evs)]) == 0
    plans = json.loads(capsys.readouterr().out)
    assert [p["action"] for p in plans] == ["freeze", "backup_reload"]


def test_policy_test_avc(tmp_path, capsys):
    avc = {
        "kind": "avc", "serial": 1, "denied": True, "perms": ["read"],
        "scontext": "u:r:httpd_t:s0", "scontext_type": "httpd_t", "tcontext": "x", "tclass": "file",
    }  # fmt: skip
    evs = [{**avc, "serial": i, "ts_us": 1_000_000 + i} for i in range(5)]
    assert main(_event(tmp_path, evs)) == 0
    assert "denials" in capsys.readouterr().out


def test_policy_test_bad_input(tmp_path, capsys):
    assert main(_event(tmp_path, {"kind": "nope"})) == 1
    assert "kind" in capsys.readouterr().err
    assert main(_event(tmp_path, {"kind": "psi"})) == 1
    f = tmp_path / "missing.json"
    assert main(["policy", "test", "--event", str(f), *CFG]) == 1
