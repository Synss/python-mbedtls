"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from functools import partial
import hashlib
import hmac
import inspect

import pytest

# pylint: disable=import-error
from mbedtls._md import MD_NAME
import mbedtls.hash as md_hash
import mbedtls.hmac as md_hmac
# pylint: enable=import-error


@pytest.fixture(params=md_hash.algorithms_available)
def algorithm(request):
    name = request.param
    return md_hash.new(name)


def make_chunks(buffer, size):
    for i in range(0, len(buffer), size):
        yield buffer[i:i+size]


def test_make_chunks(randbytes):
    buffer = randbytes(1024)
    assert b"".join(buf for buf in make_chunks(buffer, 100)) == buffer


def test_md_list():
    assert len(MD_NAME) == 10


def test_algorithms():
    assert set(md_hash.algorithms_guaranteed).issubset(
        md_hash.algorithms_available)


def test_type_accessor(algorithm):
    # pylint: disable=protected-access
    assert 0 <= algorithm._type < len(MD_NAME)


def test_copy_hash(algorithm, randbytes):
    buf0 = randbytes(512)
    buf1 = randbytes(512)
    copy = algorithm.copy()
    algorithm.update(buf1)
    copy.update(buf1)
    assert algorithm.digest() == copy.digest()


def test_check_hexdigest_against_hashlib(algorithm, randbytes):
    buf = randbytes(1024)
    try:
        alg = md_hash.new(algorithm.name, buf)
        ref = hashlib.new(algorithm.name, buf)
    except ValueError as exc:
        # Unsupported hash type.
        pytest.skip(str(exc))
    assert alg.hexdigest() == ref.hexdigest()


def test_check_against_hashlib_nobuf(algorithm, randbytes):
    buf = randbytes(1024)
    try:
        alg = md_hash.new(algorithm.name, buf)
        ref = hashlib.new(algorithm.name, buf)
    except ValueError as exc:
        # Unsupported hash type.
        pytest.skip(str(exc))
    assert alg.digest() == ref.digest()


def test_check_against_hashlib_buf(algorithm, randbytes):
    buf = randbytes(4096)
    try:
        alg = md_hash.new(algorithm.name)
        ref = hashlib.new(algorithm.name)
    except ValueError as exc:
        # Unsupported hash type.
        pytest.skip(str(exc))
    for chunk in make_chunks(buf, 500):
        alg.update(chunk)
        ref.update(chunk)
    assert alg.digest() == ref.digest()


def test_check_against_hmac_nobuf(algorithm, randbytes):
    buf = randbytes(1024)
    key = randbytes(16)
    try:
        alg = md_hmac.new(key, buf, digestmod=algorithm.name)
        ref = hmac.new(key, buf, digestmod=partial(hashlib.new, algorithm.name))
    except ValueError as exc:
        # Unsupported hash type.
        pytest.skip(str(exc))
    assert alg.digest() == ref.digest()


def test_check_against_hmac_buf(algorithm, randbytes):
    buf = randbytes(4096)
    key = randbytes(16)
    try:
        alg = md_hmac.new(key, digestmod=algorithm.name)
        ref = hmac.new(key, digestmod=partial(hashlib.new, algorithm.name))
    except ValueError as exc:
        # Unsupported hash type.
        pytest.skip(str(exc))
    for chunk in make_chunks(buf, 500):
        alg.update(chunk)
        ref.update(chunk)
    assert alg.digest() == ref.digest()


@pytest.mark.parametrize("name, algcls", inspect.getmembers(md_hash))
def test_hash_instantiation(name, algcls):
    if name not in md_hash.algorithms_available:
        pytest.skip("not a hash algorithm")
    alg1 = algcls()
    alg2 = md_hash.new(name)
    assert type(alg1) is type(alg2)
    assert alg1.name == alg2.name


@pytest.mark.parametrize("name, algcls", inspect.getmembers(md_hmac))
def test_hmac_instantiation(name, algcls, randbytes):
    if name not in md_hash.algorithms_available:
        pytest.skip("not an hmac algorithm")
    key = randbytes(16)
    alg1 = algcls(key)
    alg2 = md_hmac.new(key, digestmod=name)
    assert type(alg1) is type(alg2)
    assert alg1.name == alg2.name
