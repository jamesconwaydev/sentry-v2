import datetime as dt
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from sentry_v2.bundle import (
    SCHEMA_ID,
    BundleContext,
    HostInfo,
    Redactor,
    build_alert_bundle,
    build_bundle,
)
from sentry_v2.config_types import RedactionConfig
from sentry_v2.events import AvcEvent, Correlation, Incident, UnitEvent
from sentry_v2.sinks.base import bundle_filename

ROOT = Path(__file__).parents[2]
SCHEMA = json.loads((ROOT / "docs/reference/bundle.schema.json").read_text())

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def validate(inst: Any, schema: dict[str, Any], path: str = "$") -> None:
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        assert any(isinstance(inst, TYPES[x]) for x in ts), f"{path}: not {t}"
    if "pattern" in schema:
        assert re.search(schema["pattern"], inst), f"{path}: {inst!r} fails pattern"
    if "enum" in schema:
        assert inst in schema["enum"], f"{path}: {inst!r} not in enum"
    if isinstance(inst, dict):
        for k in schema.get("required", []):
            assert k in inst, f"{path}: missing {k}"
        props = schema.get("properties", {})
        for k, v in inst.items():
            if k in props:
                validate(v, props[k], f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                raise AssertionError(f"{path}: extra key {k}")
    if isinstance(inst, list) and "items" in schema:
        for i, v in enumerate(inst):
            validate(v, schema["items"], f"{path}[{i}]")


def avc(raw: str = "avc: denied") -> AvcEvent:
    return AvcEvent(
        ts_us=1,
        serial=1,
        denied=True,
        perms=("read",),
        scontext="a:b:c",
        scontext_type="c",
        tcontext="x:y:z",
        tclass="file",
        raw=raw,
    )


def incident(raw: str = "avc: denied", conf: float = 0.5) -> Incident:
    trig = UnitEvent(ts_us=1, unit="a.service", kind="failed", result="timeout")
    return Incident(
        id="i1",
        kind="unit_failed",
        ts_us=1,
        target="a.service",
        trigger=trig,
        related=(avc(raw),),
        correlations=(Correlation(avc(raw), conf, ("same unit",)),),
    )


def rec(**kw: Any) -> dict[str, Any]:
    base = {
        "id": "r1",
        "policy": "p",
        "action": "throttle",
        "target": "a.service",
        "mode": "dry-run",
        "configured_mode": "dry-run",
        "status": "dry_run",
        "previous": None,
        "params": {},
        "applied_at": None,
        "expires_at": None,
        "error": None,
        "incident_id": "i1",
    }
    return base | kw


HOST = HostInfo("h", "mid", "6.12", "Rocky")
CTX = BundleContext(
    psi={"memory": {"some": {"avg10": 1.0}}},
    unit_props={"ExecStart": ["/bin/x --token=abc123"]},
    journal_tail=[{"MESSAGE": "Authorization: Bearer abc.def== ok", "PRIORITY": "6"}],
)
RED = Redactor.from_config(RedactionConfig())


def test_bundle_validates_and_writes_sample(tmp_path: Path) -> None:
    b = build_bundle(incident(), [rec()], CTX, HOST, RED)
    validate(b, SCHEMA)
    assert b["schema"] == SCHEMA_ID
    assert b["ts"].endswith("Z") and re.search(r"\.\d{6}Z$", b["ts"])
    bundle_filename(b)
    assert b["decision"]["policy"] == "p"
    sample = Path(os.environ.get("SENTRY_BUNDLE_SAMPLE") or tmp_path / "bundle_sample.json")
    sample.write_text(json.dumps(b, indent=2) + "\n")


def test_schema_rejects_extra_top_level_key() -> None:
    b = build_bundle(incident(), [], CTX, HOST, RED) | {"x": 1}
    with pytest.raises(AssertionError):
        validate(b, SCHEMA)


def test_no_records_and_context_none() -> None:
    b = build_bundle(incident(), [], BundleContext({}, None, []), HOST, RED)
    assert b["decision"] == {"policy": None, "mode": None, "actions": []}
    assert b["severity"] == "info"
    validate(b, SCHEMA)


@pytest.mark.parametrize(
    ("records", "conf", "sev"),
    [
        ([rec(status="rollback_failed")], 0.1, "critical"),
        ([rec(mode="enforce", status="applied")], 0.1, "warning"),
        ([rec(mode="enforce", status="rolled_back")], 0.1, "warning"),
        ([rec(mode="enforce", status="failed")], 0.1, "info"),
        ([rec()], 0.8, "warning"),
        ([rec()], 0.79, "info"),
    ],
)
def test_severity(records: list[dict[str, Any]], conf: float, sev: str) -> None:
    assert build_bundle(incident(conf=conf), records, CTX, HOST, RED)["severity"] == sev


def test_redaction_applied_in_paths_only() -> None:
    leaky = "token=hunter2"
    b = build_bundle(incident(raw=leaky), [rec()], CTX, HOST, RED)
    assert "hunter2" not in json.dumps(b)
    assert "abc123" not in json.dumps(b)
    assert "Bearer" not in b["context"]["journal"][0]["MESSAGE"]
    assert b["incident"]["id"] == "i1"
    assert b["id"] and b["decision"]["actions"][0]["id"] == "r1"


def test_alert_bundle() -> None:
    b = build_alert_bundle("breaker_open", {"target": "a.service", "record": rec()}, HOST)
    validate(b, SCHEMA)
    assert b["severity"] == "critical"
    assert b["incident"] == {"kind": "alert", "target": "a.service", "alert": "breaker_open"}
    assert len(b["decision"]["actions"]) == 1
    b = build_alert_bundle("rollback_failed", {}, HOST)
    assert b["decision"]["actions"] == []
    validate(b, SCHEMA)


PEM = "x -----BEGIN RSA PRIVATE KEY-----\nAAA\nBBB\n-----END RSA PRIVATE KEY----- y"


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer abc.DEF-1/2+x==",
        "postgres://user:pw@host/db",
        "key AKIAABCDEFGHIJKLMNOP",
        PEM,
        "PASSWORD=x1 passwd=x2 secret=x3 Token=x4",
    ],
)
def test_default_patterns(text: str) -> None:
    out = RED.scrub(text)
    assert "[REDACTED]" in out
    for leak in ("abc.DEF", "pw@", "AKIAABCD", "AAA", "x1", "x2", "x3", "x4"):
        assert leak not in out


def test_pem_keeps_surroundings() -> None:
    assert RED.scrub(PEM) == "x [REDACTED] y"


def test_user_patterns_with_and_without_defaults() -> None:
    both = Redactor.from_config(RedactionConfig(patterns=(r"cust-\d+",)))
    assert both.scrub("cust-42 token=a") == "[REDACTED] [REDACTED]"
    only = Redactor.from_config(RedactionConfig(patterns=(r"cust-\d+",), use_defaults=False))
    assert only.scrub("cust-42 token=a") == "[REDACTED] token=a"


def test_host_collect(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_text("abc\n")
    (tmp_path / "etc/os-release").write_text('NAME="R"\nPRETTY_NAME="Rocky Linux 10"\n')
    h = HostInfo.collect(tmp_path)
    assert (h.machine_id, h.os_release) == ("abc", "Rocky Linux 10")
    assert h.hostname and h.kernel


def test_host_collect_unreadable(tmp_path: Path) -> None:
    h = HostInfo.collect(tmp_path)
    assert h.machine_id is None and h.os_release is None
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("NAME=x\n")
    assert HostInfo.collect(tmp_path).os_release is None


def test_unterminated_pem_redacted() -> None:
    assert RED.scrub("a -----BEGIN PRIVATE KEY-----\nAAAA") == "a [REDACTED]"


def test_many_begin_markers_fast() -> None:
    t = time.monotonic()
    RED.scrub("-----BEGIN PRIVATE KEY-----" * 5000)
    assert time.monotonic() - t < 0.5


def test_scrub_tree_non_json_leaves() -> None:
    u = uuid.uuid4()
    out = RED.scrub_tree(
        {"b": b"token=zz \xff", "d": dt.datetime(2026, 1, 1, tzinfo=dt.UTC), "u": u, "n": 3}
    )
    assert out["b"] == "[REDACTED] \ufffd"
    assert out["d"] == "2026-01-01 00:00:00+00:00"
    assert out["u"] == str(u) and out["n"] == 3
    json.dumps(out)


def test_action_error_scrubbed_and_copied() -> None:
    r = rec(error="boom password=x", params={"k": [1]})
    b = build_bundle(incident(), [r], CTX, HOST, RED)
    assert b["decision"]["actions"][0]["error"] == "boom [REDACTED]"
    b["decision"]["actions"][0]["params"]["k"].append(2)
    assert r["params"] == {"k": [1]}


def test_host_collect_bad_bytes(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_bytes(b"\xff\xfe")
    assert HostInfo.collect(tmp_path).machine_id is None
