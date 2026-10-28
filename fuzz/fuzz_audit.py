"""Coverage-guided fuzzing of the audit parsers: the kernel and audit.log feed them."""

import sys

import atheris

with atheris.instrument_imports():
    from sentry_v2.collectors.audit import (
        NETLINK_TYPES,
        AvcAssembler,
        LogTailSource,
        parse_audit_text,
        parse_netlink,
    )

TYPES = sorted(set(NETLINK_TYPES.values()))


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    for _, text in parse_netlink(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))):
        assert isinstance(text, str)
    asm = AvcAssembler()
    for i in range(fdp.ConsumeIntInRange(0, 8)):
        rec = parse_audit_text(fdp.PickValueInList(TYPES), fdp.ConsumeUnicodeNoSurrogates(512))
        if rec is not None:
            asm.feed(rec, float(i))
    asm.flush(float("inf"))
    LogTailSource._parse(fdp.ConsumeUnicodeNoSurrogates(1024))


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
