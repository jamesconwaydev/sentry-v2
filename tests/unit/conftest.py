from collections.abc import Iterator
from pathlib import Path

import pytest
from sinkfixtures import HttpsServer, make_cert, serve_https


@pytest.fixture(scope="session")
def tls_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    pair = make_cert(tmp_path_factory.mktemp("tls"))
    if pair is None:
        pytest.skip("neither cryptography nor openssl is available")
    return pair


@pytest.fixture
def https_server(tls_cert: tuple[Path, Path]) -> Iterator[HttpsServer]:
    yield from serve_https(*tls_cert)
