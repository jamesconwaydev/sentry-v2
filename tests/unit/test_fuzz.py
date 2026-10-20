"""Property-based fuzzing of everything that parses input the daemon doesn't control.

Audit records come from the kernel and from processes writing USER_AVCs,
pressure files from cgroupfs, durations and sizes from operators. None of
it may crash a collector: a parser either returns or raises the error its
caller handles.
"""

from __future__ import annotations

import contextlib
import struct

from hypothesis import given, settings
from hypothesis import strategies as st

from sentry_v2.bundle import Redactor
from sentry_v2.cgroupfs import parse_pressure
from sentry_v2.collectors.audit import (
    NETLINK_TYPES,
    AuditRecord,
    AvcAssembler,
    LogTailSource,
    parse_audit_text,
    parse_netlink,
)
from sentry_v2.config import default_config
from sentry_v2.units import parse_duration, parse_size

settings.register_profile("ci", max_examples=300, deadline=None)
settings.load_profile("ci")

TYPES = sorted(set(NETLINK_TYPES.values()))
# Text that looks enough like an audit record to get past the stamp check
stamped = st.builds(
    lambda sec, ms, serial, body: f"audit({sec}.{ms:03d}:{serial}): {body}",
    st.integers(0, 2**40),
    st.integers(0, 999),
    st.integers(0, 2**32),
    st.text(),
)
avc_body = st.builds(
    lambda verdict, perms, pairs: f"avc:  {verdict}  {{ {perms} }} for {pairs}",
    st.sampled_from(["denied", "granted", "bogus"]),
    st.text(alphabet=st.characters(blacklist_characters="}"), max_size=30),
    st.lists(
        st.tuples(
            st.sampled_from(["pid", "comm", "exe", "scontext", "tcontext", "tclass", "name"]),
            st.text(max_size=40),
        ),
        max_size=10,
    ).map(lambda kv: " ".join(f"{k}={v}" for k, v in kv)),
)


def netlink_message(mtype: int, payload: bytes) -> bytes:
    length = 16 + len(payload)
    return struct.pack("=IHHII", length, mtype, 0, 0, 0) + payload + b"\0" * (-length % 4)


@given(st.binary(max_size=4096))
def test_parse_netlink_never_raises_on_garbage(buf: bytes) -> None:
    for mtype, text in parse_netlink(buf):
        assert isinstance(mtype, int) and isinstance(text, str)


@given(st.lists(st.tuples(st.integers(0, 65535), st.binary(max_size=200)), max_size=8))
def test_parse_netlink_splits_every_well_formed_message(msgs: list[tuple[int, bytes]]) -> None:
    out = parse_netlink(b"".join(netlink_message(t, p) for t, p in msgs))
    assert [t for t, _ in out] == [t for t, _ in msgs]


@given(st.sampled_from(TYPES), st.one_of(st.text(), stamped, stamped.map(lambda s: s + " ")))
def test_parse_audit_text_never_raises(type_name: str, text: str) -> None:
    rec = parse_audit_text(type_name, text)
    assert rec is None or isinstance(rec, AuditRecord)


@given(st.sampled_from(["AVC", "USER_AVC"]), st.integers(0, 2**40), avc_body)
def test_parse_audit_text_handles_mangled_avcs(type_name: str, sec: int, body: str) -> None:
    rec = parse_audit_text(type_name, f"audit({sec}.000:1): {body}")
    assert rec is None or rec.ts_us == sec * 1_000_000


@given(st.text())
def test_audit_log_line_parser_never_raises(line: str) -> None:
    LogTailSource._parse(line)
    LogTailSource._parse(f"type=AVC msg={line}")


@given(
    st.lists(
        st.tuples(st.sampled_from([*TYPES, "EOE"]), st.integers(0, 5), avc_body),
        max_size=30,
    )
)
def test_assembler_never_raises_whatever_order_records_arrive(
    recs: list[tuple[str, int, str]],
) -> None:
    asm = AvcAssembler()
    for i, (type_name, serial, body) in enumerate(recs):
        rec = parse_audit_text(type_name, f"audit(1.000:{serial}): {body}")
        if rec is not None:
            asm.feed(rec, float(i))
    asm.flush(float("inf"))
    assert asm.oldest_pending_us() is None


@given(st.text())
def test_parse_pressure_raises_only_what_callers_catch(text: str) -> None:
    with contextlib.suppress(ValueError, KeyError):
        parse_pressure(text)


@given(st.text(max_size=20))
def test_parse_duration_and_size_raise_only_value_error(s: str) -> None:
    for parse in (parse_duration, parse_size):
        with contextlib.suppress(ValueError):
            parse(s)


@given(st.floats(0, 1e6, allow_nan=False).map(lambda f: round(f, 3)))
def test_parse_duration_reads_back_seconds(secs: float) -> None:
    assert abs(parse_duration(f"{secs}s") - secs) < 1e-6


REDACTOR = Redactor.from_config(default_config().redaction)
secret = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=8
)


@given(st.text(), st.text())
def test_redaction_never_raises(before: str, after: str) -> None:
    assert isinstance(REDACTOR.scrub(before + after), str)


@given(st.text(max_size=40), secret, st.text(max_size=40))
def test_password_assignments_never_survive_redaction(before: str, value: str, after: str) -> None:
    out = REDACTOR.scrub(f"{before} password={value} {after}")
    assert f"password={value}" not in out
