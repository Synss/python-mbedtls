"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name

import pickle
from collections.abc import Collection
from typing import Mapping, NamedTuple

import pytest

from mbedtls import hashlib
from mbedtls import hmac as hmaclib
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


def test_algorithms():
    assert isinstance(hashlib.algorithms_guaranteed, Collection)
    assert hashlib.algorithms_guaranteed

    assert isinstance(hashlib.algorithms_available, Collection)
    assert hashlib.algorithms_available

    assert frozenset(hashlib.algorithms_guaranteed).issubset(
        hashlib.algorithms_available
    )


def test_invalid_name_raises_TypeError():
    with pytest.raises(TypeError):
        Hash(42)


def test_unavailable_cipher_raises_ValueError():
    with pytest.raises(ValueError):
        Hash("unavailable")


class TestHash:
    @pytest.fixture(params=tuple(hashlib.algorithms_available))
    def algorithm(self, request):
        return request.param

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, algorithm):
        assert isinstance(repr_(hashlib.new(algorithm, b"")), str)

    def test_pickle(self, algorithm):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(hashlib.new(algorithm, b""))

        assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(self, algorithm):
        obj = hashlib.new(algorithm, b"")

        assert obj.digest_size == SUPPORTED_SIZES[algorithm].digest_size
        assert obj.block_size == SUPPORTED_SIZES[algorithm].block_size

    def test_new_and_update(self, algorithm, randbytes):
        buffer = randbytes(512)

        obj = hashlib.new(algorithm, b"")
        obj.update(buffer)
        other = hashlib.new(algorithm, buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_update_and_copy(self, algorithm, randbytes):
        buffer = randbytes(512)

        obj = hashlib.new(algorithm, buffer)
        other = obj.copy()

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update(self, algorithm, randbytes):
        buffer = randbytes(512)

        obj = hashlib.new(algorithm, buffer)
        other = obj.copy()
        obj.update(buffer)
        other.update(buffer)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update_nothing(self, algorithm, randbytes):
        buffer = randbytes(512)

        obj = hashlib.new(algorithm, buffer)
        other = obj.copy()
        obj.update(b"")

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()


class TestHmac:
    @pytest.fixture(params=tuple(hmaclib.algorithms_available))
    def algorithm(self, request):
        return request.param

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, algorithm):
        assert isinstance(repr_(hmaclib.new(b"", digestmod=algorithm)), str)

    def test_pickle(self, algorithm):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(hmaclib.new(b"", digestmod=algorithm))

        assert str(excinfo.value).startswith("cannot pickle")

    def test_accessors(self, algorithm):
        obj = hmaclib.new(b"", digestmod=algorithm)

        assert obj.digest_size == SUPPORTED_SIZES[algorithm].digest_size
        assert obj.block_size == SUPPORTED_SIZES[algorithm].block_size

    def test_new_and_update(self, algorithm, randbytes):
        key = b"key"
        buffer = randbytes(512)

        obj = hmaclib.new(key, b"", digestmod=algorithm)
        obj.update(buffer)
        other = hmaclib.new(key, buffer, digestmod=algorithm)

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()

    def test_copy_and_update_nothing(self, algorithm, randbytes):
        key = b"key"
        buffer = randbytes(512)

        obj = hmaclib.new(key, buffer, digestmod=algorithm)
        other = hmaclib.new(key, buffer, digestmod=algorithm)
        obj.update(b"")

        assert obj.digest() == other.digest()
        assert obj.hexdigest() == other.hexdigest()
