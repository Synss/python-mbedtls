import base64

import pytest

from mbedtls import secrets


# For Python 2.7
try:
    unicode
except NameError:
    unicode = str


def test_token_bytes():
    token = secrets.token_bytes()
    assert len(token) == secrets.DEFAULT_ENTROPY
    assert isinstance(token, bytes)


@pytest.mark.parametrize("nbytes", [0, 32, 256, 500])
def test_token_bytes(nbytes):
    token = secrets.token_bytes(nbytes)
    assert len(token) == nbytes
    assert isinstance(token, bytes)


def test_token_hex():
    token = secrets.token_hex()
    assert len(token) == 2 * secrets.DEFAULT_ENTROPY
    assert isinstance(token, (str, unicode))


def test_token_urlsafe():
    token = secrets.token_urlsafe()
    assert len(token) == pytest.approx(1.3 * secrets.DEFAULT_ENTROPY, rel=0.1)
    assert isinstance(token, (str, unicode))


@pytest.mark.repeat(100)
def test_choice():
    seq = tuple(range(100))
    chosen = secrets.choice(seq)
    assert chosen in seq


def test_choice_from_empty_sequence_raises_indexerror():
    with pytest.raises(IndexError):
        secrets.choice([])


def test_randbits():
    assert 0 <= secrets.randbits(32) < (1 << 32)


@pytest.mark.repeat(100)
@pytest.mark.parametrize("upper_bound", [1, 1 << 32, 1 << 128, 1 << 1024])
def test_randbelow(upper_bound):
    assert 0 <= secrets.randbelow(upper_bound) < upper_bound
