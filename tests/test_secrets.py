# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from mbedtls import secrets


def test_token_bytes_default_entropy() -> None:
    token = secrets.token_bytes()
    assert len(token) == secrets.DEFAULT_ENTROPY
    assert isinstance(token, bytes)


@pytest.mark.parametrize("nbytes", [0, 32, 256, 500])
def test_token_bytes(nbytes: int) -> None:
    token = secrets.token_bytes(nbytes)
    assert len(token) == nbytes
    assert isinstance(token, bytes)


def test_token_hex() -> None:
    token = secrets.token_hex()
    assert len(token) == 2 * secrets.DEFAULT_ENTROPY
    assert isinstance(token, str)


def test_token_urlsafe() -> None:
    token = secrets.token_urlsafe()
    assert len(token) == pytest.approx(1.3 * secrets.DEFAULT_ENTROPY, rel=0.1)
    assert isinstance(token, str)


@pytest.mark.repeat(100)
def test_choice() -> None:
    seq = tuple(range(100))
    chosen = secrets.choice(seq)
    assert chosen in seq


def test_choice_from_empty_sequence_raises_indexerror() -> None:
    with pytest.raises(IndexError):
        secrets.choice([])


def test_randbits() -> None:
    assert 0 <= secrets.randbits(32) < (1 << 32)


@pytest.mark.parametrize("upper_bound", [0, -1])
def test_randbelow_zero_raises_valueerror(upper_bound: int) -> None:
    with pytest.raises(ValueError):
        secrets.randbelow(upper_bound)


@pytest.mark.repeat(100)
@pytest.mark.parametrize("upper_bound", [1, 1 << 32, 1 << 128, 1 << 1024])
def test_randbelow(upper_bound: int) -> None:
    assert 0 <= secrets.randbelow(upper_bound) < upper_bound
