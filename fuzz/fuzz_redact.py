"""Coverage-guided fuzzing of redaction, which runs on every string in every bundle.

A pattern that backtracks badly shows up here as a timeout.
"""

import sys

import atheris

with atheris.instrument_imports():
    from sentry_v2.bundle import DEFAULT_PATTERNS, Redactor

RED = Redactor(DEFAULT_PATTERNS)


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    before = fdp.ConsumeUnicodeNoSurrogates(256)
    secret = fdp.ConsumeUnicodeNoSurrogates(32).replace(" ", "x").replace("\n", "x")
    after = fdp.ConsumeUnicodeNoSurrogates(256)
    out = RED.scrub(f"{before} --password {secret} {after}")
    # The secret may also turn up in the text around it; only the flag's own
    # value has to go.
    if secret.isalnum():
        assert f"--password {secret}" not in out, out


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
