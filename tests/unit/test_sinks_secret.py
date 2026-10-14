import os
from pathlib import Path

import pytest

from sentry_v2.sinks.base import SinkError, load_secret


def _secret(tmp_path: Path, text: str = "s3cret\n", mode: int = 0o600) -> Path:
    p = tmp_path / "key"
    p.write_text(text)
    p.chmod(mode)
    return p


def test_reads_and_strips_trailing_newline(tmp_path: Path) -> None:
    assert load_secret(_secret(tmp_path), check_owner=False) == "s3cret"


def test_group_or_world_readable_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SinkError, match="0644"):
        load_secret(_secret(tmp_path, mode=0o644), check_owner=False)


@pytest.mark.skipif(os.geteuid() == 0, reason="root owns the file")
def test_owner_must_be_root(tmp_path: Path) -> None:
    with pytest.raises(SinkError, match="owned by root"):
        load_secret(_secret(tmp_path))


def test_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(SinkError, match="cannot read secret"):
        load_secret(tmp_path / "nope", check_owner=False)


def test_directory_is_rejected(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    with pytest.raises(SinkError, match="regular file"):
        load_secret(d, check_owner=False)


def test_empty_secret_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SinkError, match="empty"):
        load_secret(_secret(tmp_path, text="\n"), check_owner=False)


def test_relative_path_resolves_under_credentials_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _secret(tmp_path, text="from-systemd")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert load_secret(Path("key"), check_owner=False) == "from-systemd"


def test_relative_path_without_credentials_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(SinkError, match="CREDENTIALS_DIRECTORY"):
        load_secret(Path("key"), check_owner=False)
