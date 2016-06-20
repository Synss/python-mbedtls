"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from functools import partial
import hashlib
import hmac

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal, assert_greater_equal, assert_less

# pylint: disable=import-error
from mbedtls._md import MD_NAME
import mbedtls.hash as md_hash
import mbedtls.hmac as md_hmac
# pylint: enable=import-error

from . import _rnd


def make_chunks(buffer, size):
    for i in range(0, len(buffer), size):
        yield buffer[i:i+size]


def test_make_chunks():
    buffer = _rnd(1024)
    assert_equal(b"".join(buf for buf in make_chunks(buffer, 100)),
                 buffer)


def test_md_list():
    assert len(MD_NAME) == 10


def test_algorithms():
    assert set(md_hash.algorithms_guaranteed).issubset(
        md_hash.algorithms_available)


def test_type_accessor():
    def assert_in_bounds(value, lower, higher):
        assert_greater_equal(value, lower)
        assert_less(value, higher)

    for name in md_hash.algorithms_available:
        alg = md_hash.new(name)
        # pylint: disable=protected-access
        test = partial(assert_in_bounds, alg._type, 0, len(MD_NAME))
        test.description = "test_type_accessor(%s)" % name
        yield test


def test_copy_hash():
    for name in md_hash.algorithms_available:
        buf0 = _rnd(512)
        buf1 = _rnd(512)
        alg = md_hash.new(name, buf0)
        copy = alg.copy()
        alg.update(buf1)
        copy.update(buf1)
        # Use partial to have the correct name in failed reports (by
        # avoiding late bindings).
        test = partial(assert_equal, alg.digest(), copy.digest())
        test.description = "test_copy_hash(%s)" % name
        yield test


def test_check_hexdigest_against_hashlib():
    for name in md_hash.algorithms_available:
        buf = _rnd(1024)
        try:
            alg = md_hash.new(name, buf)
            ref = hashlib.new(name, buf)
        except ValueError as exc:
            # Unsupported hash type.
            raise SkipTest(str(exc)) from exc
        test = partial(assert_equal, alg.hexdigest(), ref.hexdigest())
        test.description = "check_hexdigest_against_hashlib(%s)" % name
        yield test


def test_check_against_hashlib_nobuf():
    for name in md_hash.algorithms_available:
        buf = _rnd(1024)
        try:
            alg = md_hash.new(name, buf)
            ref = hashlib.new(name, buf)
        except ValueError as exc:
            # Unsupported hash type.
            raise SkipTest(str(exc)) from exc
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hashlib_nobuf(%s)" % name
        yield test


def test_check_against_hashlib_buf():
    for name in md_hash.algorithms_available:
        buf = _rnd(4096)
        try:
            alg = md_hash.new(name)
            ref = hashlib.new(name)
        except ValueError as exc:
            # Unsupported hash type.
            raise SkipTest(str(exc)) from exc
        for chunk in make_chunks(buf, 500):
            alg.update(chunk)
            ref.update(chunk)
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hashlib_buf(%s)" % name
        yield test


def test_check_against_hmac_nobuf():
    for name in md_hmac.algorithms_available:
        buf = _rnd(1024)
        key = _rnd(16)
        try:
            alg = md_hmac.new(key, buf, digestmod=name)
            ref = hmac.new(key, buf, digestmod=name)
        except ValueError as exc:
            # Unsupported hash type.
            raise SkipTest(str(exc)) from exc
        # Use partial to have the correct name in failed reports (by
        # avoiding late bindings).
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hmac_nobuf(%s)" % name
        yield test


def test_check_against_hmac_buf():
    for name in md_hmac.algorithms_available:
        buf = _rnd(4096)
        key = _rnd(16)
        try:
            alg = md_hmac.new(key, digestmod=name)
            ref = hmac.new(key, digestmod=name)
        except ValueError as exc:
            # Unsupported hash type.
            raise SkipTest(str(exc)) from exc
        for chunk in make_chunks(buf, 500):
            alg.update(chunk)
            ref.update(chunk)
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hmac_buf(%s)" % name
        yield test


def test_hash_instantiation():
    import inspect

    def check_instantiation(fun, name):
        alg1 = fun()
        alg2 = md_hash.new(name)
        assert_equal(type(alg1), type(alg2))
        assert_equal(alg1.name, alg2.name)

    for name, member in inspect.getmembers(md_hash):
        if name in md_hash.algorithms_available:
            test = partial(check_instantiation, member, name)
            test.description = "check_hash_instantiation(%s)" % name
            yield test


def test_hmac_instantiation():
    import inspect

    def check_instantiation(fun, name):
        key = _rnd(16)
        alg1 = fun(key)
        alg2 = md_hmac.new(key, digestmod=name)
        assert_equal(type(alg1), type(alg2))
        assert_equal(alg1.name, alg2.name)

    for name, member in inspect.getmembers(md_hmac):
        if name in md_hmac.algorithms_available:
            test = partial(check_instantiation, member, name)
            test.description = "check_hmac_instantiation(%s)" % name
            yield test
