import contextlib
import io
import json
import shutil
import socket
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from sentry_v2.cli import main
from sentry_v2.client import ControlClient, ControlError, NotRunning, PermissionDenied

FIX = Path(__file__).parent.parent / "fixtures" / "config"
CFG = ["--config", str(FIX / "minimal.toml"), "--policies", str(FIX / "policies.d")]

STATUS = {
    "version": "0.2.1",
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
        self.replies: dict[str, Any] = {}
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
            with contextlib.suppress(BrokenPipeError), c, c.makefile("rwb") as f:
                req = json.loads(f.readline())
                self.seen.append(req)
                if req["cmd"] == "subscribe":
                    f.write(b'{"id":1,"ok":true,"result":{}}\n{"event":{"a":1}}\n')
                elif isinstance(self.replies[req["cmd"]], bytes):
                    f.write(self.replies[req["cmd"]])
                    if self.replies[req["cmd"]] == b"hang":
                        threading.Event().wait(1)
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


ID_A = "0199f2b4-1d2e-7a00-8c11-2f3e4d5c6b7a"
ID_B = "0199f2b4-1d2e-7a00-9d22-3f4e5d6c7b8a"  # same timestamp bits as ID_A


def test_rollback_ok_and_err(stub, capsys):
    stub.replies["rollback"] = {"ok": True, "result": {"rolled_back": [{"id": ID_A}]}}
    rc, out, _ = run(stub, capsys, "rollback", ID_A)
    assert rc == 0 and ID_A in out and stub.seen[-1]["args"] == {"id": ID_A}
    assert [r["cmd"] for r in stub.seen] == ["rollback"]  # a full id needs no lookup
    stub.replies["rollback"] = {"ok": False, "error": "no such action"}
    rc, _, err = run(stub, capsys, "rollback", ID_B)
    assert rc == 1 and "no such action" in err
    run(stub, capsys, "rollback", "--all")
    assert stub.seen[-1]["args"] == {"all": True}


def test_rollback_resolves_a_short_id(stub, capsys):
    stub.replies["actions"] = {
        "ok": True,
        "result": {"active": [{"id": ID_A}], "recent": [{"id": ID_A}, {"id": ID_B}]},
    }
    stub.replies["rollback"] = {"ok": True, "result": {"rolled_back": [{"id": ID_A}]}}
    for short in ("2f3e4d5c6b7a", "4d5c6b7a", "0199f2b4-1d2e-7a00-8c", "4D5C6B7A"):
        rc, _, err = run(stub, capsys, "rollback", short)
        assert rc == 0, err
        assert stub.seen[-1] == {"id": 1, "cmd": "rollback", "args": {"id": ID_A}}

    rc, _, err = run(stub, capsys, "rollback", "0199f2b4")
    assert rc == 1 and ID_A in err and ID_B in err and "more than one" in err
    rc, _, err = run(stub, capsys, "rollback", "ffffff")
    assert rc == 1 and "no recent action" in err
    seen = len(stub.seen)
    rc, _, err = run(stub, capsys, "rollback", "6b7a")
    assert rc == 1 and "at least 6" in err and len(stub.seen) == seen


def test_id_column_shows_the_random_end_of_the_id(stub, capsys):
    stub.replies["actions"] = {
        "ok": True,
        "result": {"active": [], "recent": [{"id": ID_A}, {"id": ID_B}]},
    }
    _, out, _ = run(stub, capsys, "actions")
    assert "4d5c6b7a" in out and "5d6c7b8a" in out and "0199f2b4" not in out


def test_simple_commands(stub, capsys):
    stub.replies |= {
        "pause": {"ok": True, "result": {"paused": True}},
        "resume": {"ok": True, "result": {"paused": False}},
        "reload": {"ok": True, "result": {"reloaded": True}},
        "restore": {
            "ok": True,
            "result": {"restored": ["/etc/x"], "skipped": ["/usr/y"], "note": "reload it"},
        },
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
    _, out, _ = run(stub, capsys, "restore", "u.service/20260101T000000Z")
    assert out == "restored:\n/etc/x\nalready matched the backup:\n/usr/y\nreload it\n"
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
    "total_us": 1, "triggered": True, "stall_us": 300000, "window_us": 2000000,
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


def test_client_bad_replies(stub, capsys):
    stub.replies["status"] = b'{"id":1,"ok":tr'  # closes after half a line
    rc, _, err = run(stub, capsys, "status")
    assert rc == 1 and "daemon did not answer" in err
    stub.replies["status"] = b"not json\n"
    assert run(stub, capsys, "status")[0] == 1
    stub.replies["status"] = b"[1]\n"
    assert run(stub, capsys, "status")[0] == 1
    stub.replies["status"] = b'{"id":7,"ok":true,"result":{}}\n'
    rc, _, err = run(stub, capsys, "status")
    assert rc == 1 and "id does not match" in err


def test_client_timeout(stub):
    stub.replies["status"] = b"hang"
    with pytest.raises(ControlError, match="did not answer"):
        ControlClient(stub.path, timeout=0.1).call("status")


def test_unexpected_reply_shape(stub, capsys):
    stub.replies["status"] = {"ok": True, "result": {"version": "1"}}
    rc, _, err = run(stub, capsys, "status")
    assert rc == 1 and err.startswith("unexpected reply from the daemon")


def test_hostile_text_is_cleaned(stub, capsys):
    bad = "x\x1b[2J\ny\x9b"
    stub.replies["actions"] = {
        "ok": True,
        "result": {"active": [{"id": "a", "target": bad, "status": "applied"}], "recent": []},
    }
    rc, out, _ = run(stub, capsys, "actions")
    assert rc == 0 and "x?[2J?y?" in out and "\x1b" not in out
    stub.replies["pause"] = {"ok": False, "error": bad}
    assert "\x1b" not in run(stub, capsys, "pause")[2]


def test_colour_rules(stub, capsys, monkeypatch):
    stub.replies["actions"] = {
        "ok": True,
        "result": {"active": [{"id": "a", "status": "applied"}], "recent": []},
    }
    monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
    monkeypatch.setenv("NO_COLOR", "")
    assert "\x1b[32mapplied" in run(stub, capsys, "actions")[1]
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in run(stub, capsys, "actions")[1]


def test_empty_events_and_limit(tmp_path, capsys):
    assert main(_event(tmp_path, [])) == 1
    assert "holds no events" in capsys.readouterr().err
    assert main(["incidents", "--limit", "0"]) == 2


def test_broken_pipe(stub, capsys, monkeypatch):
    stub.replies["pause"] = {"ok": True, "result": {"paused": True}}
    monkeypatch.setattr("builtins.print", lambda *a, **k: (_ for _ in ()).throw(BrokenPipeError))
    assert main(["--socket", str(stub.path), "pause"]) == 0


def test_odd_reply_shapes(stub, capsys):
    stub.replies["status"] = {"ok": True, "result": {**STATUS, "collectors": []}}
    rc, _, err = run(stub, capsys, "status")
    assert rc == 1 and "unexpected reply" in err
    act = {"id": "a", "status": "applied", "expires_at": 1e300}
    stub.replies["actions"] = {"ok": True, "result": {"active": [act], "recent": []}}
    rc, out, _ = run(stub, capsys, "actions")
    assert rc == 0 and "a very long time" in out


def test_error_ignores_id_and_bool_id_rejected(stub):
    stub.replies["x"] = b'{"id":9,"ok":false,"error":"nope"}\n'
    with pytest.raises(ControlError, match="nope"):
        ControlClient(stub.path).call("x")
    stub.replies["y"] = b'{"id":true,"ok":true,"result":{}}\n'
    with pytest.raises(ControlError, match="id does not match"):
        ControlClient(stub.path).call("y")


def test_bidi_stripped(stub, capsys):
    stub.replies["actions"] = {
        "ok": True,
        "result": {"active": [{"id": "a", "target": "a\u202eb"}], "recent": []},
    }
    assert "\u202e" not in run(stub, capsys, "actions")[1]


POLICIES = {
    "policies": [
        {
            "name": "memory-hog",
            "mode": "enforce",
            "effective_mode": "dry-run",
            "signal": "psi",
            "actions": ["throttle", "notify"],
            "source": "/etc/sentry-v2/policies.d/10-memory.toml",
        }
    ],
    "last_reload_error": "99-bad.toml: policy[0].when.bogus: unknown key",
}


def test_policies(stub, capsys):
    stub.replies["policies"] = {"ok": True, "result": POLICIES}
    rc, out, _ = run(stub, capsys, "policies")
    assert rc == 0
    assert "memory-hog" in out and "throttle, notify" in out and "10-memory.toml" in out
    assert "last reload failed: 99-bad.toml: policy[0].when.bogus" in out
    rc, out, _ = run(stub, capsys, "policies", "--json")
    assert rc == 0 and json.loads(out) == POLICIES


def test_rollback_and_restore_wait_longer(stub, capsys, monkeypatch):
    timeouts: dict[str, float] = {}
    real_call = ControlClient.call

    def spy(self, cmd, **args):
        timeouts[cmd] = self.timeout
        return real_call(self, cmd, **args)

    monkeypatch.setattr(ControlClient, "call", spy)
    stub.replies |= {
        "rollback": {"ok": True, "result": {"rolled_back": []}},
        "restore": {"ok": True, "result": {"restored": [], "skipped": [], "note": "n"}},
        "pause": {"ok": True, "result": {"paused": True}},
    }
    _, _, err = run(stub, capsys, "rollback", "--all")
    assert err == ""  # not a terminal
    run(stub, capsys, "restore", "u.service/20260101T000000Z")
    run(stub, capsys, "pause")
    assert timeouts == {"rollback": 900.0, "restore": 900.0, "pause": 10.0}

    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    _, _, err = run(stub, capsys, "rollback", "--all")
    assert err == "Rolling back… this can take a while if systemd is slow\n"


def test_redact_file_stdin_and_json(tmp_path, capsys, monkeypatch):
    f = tmp_path / "t.txt"
    f.write_text("app --password hunter2 --port 80\n")
    assert main(["redact", str(f), *CFG]) == 0
    assert capsys.readouterr().out == "app [REDACTED] --port 80\n"
    monkeypatch.setattr("sys.stdin", io.StringIO("token=a [REDACTED] b"))
    assert main(["--json", "redact", *CFG]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "redactions": 1,
        "text": "[REDACTED] [REDACTED] b",
    }


def test_redact_uses_configured_patterns(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[redaction]\npatterns = ['cust-\\d+']\nuse_defaults = false\n")
    f = tmp_path / "t.txt"
    f.write_text("cust-42 token=a")
    args = ["--config", str(cfg), "--policies", str(tmp_path / "none")]
    assert main(["redact", str(f), *args]) == 0
    assert capsys.readouterr().out == "[REDACTED] token=a"


def test_redact_errors(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("[redaction]\npatterns = ['(']\n")
    assert main(["redact", "x", "--config", str(bad), "--policies", str(tmp_path / "none")]) == 1
    assert "invalid:" in capsys.readouterr().err
    assert main(["redact", str(tmp_path / "missing"), *CFG]) == 1
    assert "cannot read" in capsys.readouterr().err


def _bundle(tmp_path, incident):
    return _event(tmp_path, {"schema": "sentry-v2/bundle/1", "incident": incident})


def test_policy_test_replays_saved_bundles(tmp_path, capsys):
    unit = {"source": "journal", "kind": "failed", "ts_us": 5_000_000,
            "unit": "batch-1.service", "result": "watchdog", "main_pid": None}  # fmt: skip
    assert main(["--json", *_bundle(tmp_path, {"kind": "unit_failed", "trigger": unit})]) == 0
    assert [p["action"] for p in json.loads(capsys.readouterr().out)] == ["freeze", "backup_reload"]

    psi = {**{k: v for k, v in PSI.items() if k not in ("kind", "pressure")}, "source": "psi"}
    assert main(_bundle(tmp_path, {"kind": "psi", "trigger": {**psi, "kind": "full"}})) == 0
    assert "memory_high=80%" in capsys.readouterr().out

    avc = {"source": "audit", "serial": 1, "denied": True, "perms": ["read"], "ts_us": 1_000_000,
           "scontext": "u:r:httpd_t:s0", "scontext_type": "httpd_t", "tcontext": "x",
           "tclass": "file"}  # fmt: skip
    related = [{**avc, "serial": i, "ts_us": 1_000_000 + i} for i in range(1, 5)]
    inc = {"kind": "avc", "trigger": avc, "related": related,
           "correlations": [{"avc": related[0], "confidence": 1.0, "reasons": []}]}  # fmt: skip
    assert main(_bundle(tmp_path, inc)) == 0
    assert "denials" in capsys.readouterr().out


def test_policy_test_alert_bundle_has_nothing_to_replay(tmp_path, capsys):
    assert main(_bundle(tmp_path, {"kind": "alert", "target": "a.service"})) == 1
    assert "alert bundle has no events" in capsys.readouterr().err


def test_ack_and_held_in_status(stub, capsys):
    stub.replies["ack"] = {"ok": True, "result": {"acknowledged": "app.service"}}
    rc, out, _ = run(stub, capsys, "ack", "app.service")
    assert rc == 0 and "acknowledged app.service" in out
    assert stub.seen[-1]["args"] == {"unit": "app.service"}
    stub.replies["status"] = {
        "ok": True,
        "result": {**STATUS, "held": [{"unit": "app.service", "since": 1.0}]},
    }
    rc, out, _ = run(stub, capsys, "status")
    assert "HELD" in out and "app.service" in out and "sentry-v2ctl ack UNIT" in out
