"""Diagnostic bundles: one JSON document per incident, scrubbed of secrets."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentry_v2.config_types import RedactionConfig
from sentry_v2.events import Incident
from sentry_v2.ids import uuid7

SCHEMA_ID = "sentry-v2/bundle/1"
REDACTED = "[REDACTED]"

DEFAULT_PATTERNS = (
    # before the bearer pattern, which would leave "Authorization: [REDACTED]"
    # for this one to swallow the next word after
    r"(?i)authorization:\s*\S+(?:\s+\S+)?",
    r"(?i)bearer\s+[a-z0-9._~+/-]+=*",
    r"://[^/\s:@]+:[^/\s@]+@",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)=\S+",
)


class Redactor:
    def __init__(self, patterns: Sequence[str]) -> None:
        self._res = [re.compile(p) for p in patterns]

    @classmethod
    def from_config(cls, cfg: RedactionConfig) -> Redactor:
        return cls((*DEFAULT_PATTERNS, *cfg.patterns) if cfg.use_defaults else cfg.patterns)

    def scrub(self, text: str) -> str:
        for r in self._res:
            text = r.sub(REDACTED, text)
        return text

    def scrub_tree(self, obj: Any) -> Any:
        """Return a copy of a JSON-like tree with every string scrubbed."""
        if isinstance(obj, bytes):
            return self.scrub(obj.decode(errors="replace"))
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, Mapping):
            return {k: self.scrub_tree(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub_tree(v) for v in obj]
        if isinstance(obj, float):
            return obj if math.isfinite(obj) else None  # NaN/inf are not valid JSON
        if obj is None or isinstance(obj, (bool, int)):
            return obj
        return self.scrub(str(obj))


@dataclass(frozen=True)
class HostInfo:
    hostname: str
    machine_id: str | None
    kernel: str
    os_release: str | None

    @classmethod
    def collect(cls, root: Path = Path("/")) -> HostInfo:
        try:
            machine_id: str | None = (root / "etc/machine-id").read_text().strip()
        except (OSError, ValueError):
            machine_id = None
        os_release = None
        try:
            for line in (root / "etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    os_release = line.partition("=")[2].strip().strip("\"'")
        except (OSError, ValueError):
            pass
        return cls(os.uname().nodename, machine_id, os.uname().release, os_release)

    def to_dict(self) -> dict[str, str | None]:
        return {
            "hostname": self.hostname,
            "machine_id": self.machine_id,
            "kernel": self.kernel,
            "os_release": self.os_release,
        }


@dataclass(frozen=True)
class BundleContext:
    psi: dict[str, dict[str, Any]]
    unit_props: dict[str, Any] | None
    journal_tail: list[dict[str, Any]]


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _action(rec: Mapping[str, Any], redactor: Redactor) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(json.dumps(rec, default=str))
    if isinstance(out.get("error"), str):
        out["error"] = redactor.scrub(out["error"])
    return out


def _severity(records: Sequence[Mapping[str, Any]], incident: Mapping[str, Any]) -> str:
    if any(r.get("status") == "rollback_failed" for r in records):
        return "critical"
    enforced = any(
        r.get("mode") == "enforce" and r.get("status") in ("applied", "rolled_back")
        for r in records
    )
    strong = any(c["confidence"] >= 0.8 for c in incident["correlations"])
    return "warning" if enforced or strong else "info"


def build_bundle(
    incident: Incident,
    records: Sequence[Mapping[str, Any]],
    context: BundleContext,
    host: HostInfo,
    redactor: Redactor,
) -> dict[str, Any]:
    inc = json.loads(json.dumps(incident.to_dict()))  # tuples become lists
    # Explicit scrub paths: ids and contexts must not be mangled.
    scrub = redactor.scrub
    trigger: dict[str, Any] = inc["trigger"]
    if isinstance(trigger.get("raw"), str):
        trigger["raw"] = scrub(trigger["raw"])
    for ev in inc["related"]:
        if isinstance(ev.get("raw"), str):
            ev["raw"] = scrub(ev["raw"])
    corrs = [{**c, "avc": {**c["avc"], "raw": scrub(c["avc"]["raw"])}} for c in inc["correlations"]]
    inc["correlations"] = corrs
    first = records[0] if records else {}
    return {
        "schema": SCHEMA_ID,
        "id": uuid7(),
        "ts": _now(),
        "severity": _severity(records, inc),
        "host": host.to_dict(),
        "incident": inc,
        "context": {
            "psi": context.psi,
            "unit": redactor.scrub_tree(context.unit_props),
            "journal": redactor.scrub_tree(context.journal_tail),
        },
        "correlations": corrs,
        "decision": {
            "policy": first.get("policy"),
            "mode": first.get("mode"),
            "actions": [_action(r, redactor) for r in records],
        },
    }


def build_alert_bundle(kind: str, detail: Mapping[str, Any], host: HostInfo) -> dict[str, Any]:
    record = detail.get("record")
    return {
        "schema": SCHEMA_ID,
        "id": uuid7(),
        "ts": _now(),
        "severity": "critical",
        "host": host.to_dict(),
        "incident": {"kind": "alert", "target": detail.get("target"), "alert": kind},
        "context": {"psi": {}, "unit": None, "journal": []},
        "correlations": [],
        "decision": {"policy": None, "mode": None, "actions": [record] if record else []},
    }
