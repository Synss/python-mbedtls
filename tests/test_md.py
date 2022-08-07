# SPDX-License-Identifier: MIT

"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from __future__ import annotations

import pickle
from collections.abc import Collection
from typing import Any, Callable, Mapping, NamedTuple, cast

import pytest

from mbedtls import hashlib, hmac
from mbedtls._md import Hash


class Size(NamedTuple):
    digest_size: int
    block_size: int


SUPPORTED_SIZES: Mapping[str, Size] = {
    "md2": Size(digest_size=16, block_size=16),
    "md4": Size(digest_size=16, block_size=64),
    "md5": Size(digest_size=16, block_size=64),
    "sha1": Size(digest_size=20, block_size=64),
    "sha224": Size(digest_size=28, block_size=64),
    "sha256": Size(digest_size=32, block_size=64),
    "sha384": Size(digest_size=48, block_size=128),
    "sha512": Size(digest_size=64, block_size=128),
    "ripemd160": Size(digest_size=20, block_size=64),
}


def test_algorithms() -> None:
    assert isinstance(hashlib.algorithms_guaranteed, Collection)
    assert hashlib.algorithms_guaranteed

    assert isinstance(hashlib.algorithms_available, Collection)
    assert hashlib.algorithms_available

    assert frozenset(hashlib.algorithms_guaranteed).issubset(
        hashlib.algorithms_available
    )


def test_invalid_name_raises_TypeError() -> None:
    with pytest.raises(TypeError):
        Hash(42)  # type: ignore[arg-type]


def test_unavailable_cipher_raises_ValueError() -> None:
    with pytest.raises(ValueError):
        Hash("unavailable")


class TestHash:
    @pytest.fixture(params=tuple(hashlib.algorithms_available))
    def algorithm_str(self, request: Any) -> str:
        assert isinstance(request.param, str)
        return request.param

    @pytest.fixture()
    def algorithm(self, algorithm_str: str) -> hashlib.Algorithm:
        return cast(hashlib.Algorithm, getattr(hashlib, algorithm_str))

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self, repr_: Callable[[object], str], algorithm: hashlib.Algorithm
    ) -> None:
        assert isinstance(repr_(algorithm(b"")), str)

    def test_pickle(self, algorithm: hashlib.Algorithm) -> None:
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(algorithm(b""))

        assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(
        self, algorithm: hashlib.Algorithm, algorithm_str: str
    ) -> None:
        obj = algorithm(b"")

        assert obj.digest_size == SUPPORTED_SIZES[algorithm_str].digest_size
        assert obj.block_size == SUPPORTED_SIZES[algorithm_str].block_size

    def test_update(
        self, algorithm: hashlib.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        buffer = randbytes(512)

        obj = algorithm(b"")
        obj.update(buffer)
        other = algorithm(buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_new(
        self,
        algorithm: hashlib.Algorithm,
        algorithm_str: str,
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = randbytes(512)

        obj = algorithm(buffer)
        other = hashlib.new(algorithm_str, buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_update_and_copy(
        self, algorithm: hashlib.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        buffer = randbytes(512)

        obj = algorithm(buffer)
        other = obj.copy()

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update(
        self, algorithm: hashlib.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        buffer = randbytes(512)

        obj = algorithm(buffer)
        other = obj.copy()
        obj.update(buffer)
        other.update(buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update_nothing(
        self, algorithm: hashlib.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        buffer = randbytes(512)

        obj = algorithm(buffer)
        other = obj.copy()
        obj.update(b"")

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()


class TestHmac:
    @pytest.fixture(params=tuple(hmac.algorithms_available))
    def algorithm_str(self, request: Any) -> str:
        assert isinstance(request.param, str)
        return request.param

    @pytest.fixture()
    def algorithm(self, algorithm_str: str) -> hmac.Algorithm:
        return cast(hmac.Algorithm, getattr(hmac, algorithm_str))

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self, repr_: Callable[[object], str], algorithm: hmac.Algorithm
    ) -> None:
        assert isinstance(repr_(algorithm(b"")), str)

    def test_pickle(self, algorithm: hmac.Algorithm) -> None:
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(algorithm(b""))

        assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(
        self, algorithm: hmac.Algorithm, algorithm_str: str
    ) -> None:
        obj = algorithm(b"")

        assert obj.digest_size == SUPPORTED_SIZES[algorithm_str].digest_size
        assert obj.block_size == SUPPORTED_SIZES[algorithm_str].block_size

    def test_update(
        self, algorithm: hmac.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        key = b"key"
        buffer = randbytes(512)

        obj = algorithm(key, b"")
        obj.update(buffer)
        other = algorithm(key, buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_new(
        self,
        algorithm: hmac.Algorithm,
        algorithm_str: str,
        randbytes: Callable[[int], bytes],
    ) -> None:
        key = b"key"
        buffer = randbytes(512)

        obj = algorithm(key, buffer)
        other = hmac.new(key, buffer, digestmod=algorithm_str)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update_nothing(
        self, algorithm: hmac.Algorithm, randbytes: Callable[[int], bytes]
    ) -> None:
        key = b"key"
        buffer = randbytes(512)

        obj = algorithm(key, buffer)
        other = algorithm(key, buffer)
        obj.update(b"")

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()
