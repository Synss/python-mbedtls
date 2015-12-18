"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from functools import partial
import hashlib
import hmac

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal

# pylint: disable=import-error
import mbedtls.md as md
from mbedtls.md import MD_NAME
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
    assert set(md.algorithms_guaranteed).issubset(md.algorithms_available)


def test_check_against_hashlib_nobuf():
    for name in md.algorithms_available:
        buf = _rnd(1024)
        alg = md.new(name, buf)
        ref = hashlib.new(name, buf)
        # Use partial to have the correct name in failed reports (by
        # avoiding late bindings).
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hashlib_nobuf(%s)" % name
        yield test


def test_check_against_hashlib_buf():
    for name in md.algorithms_available:
        buf = _rnd(4096)
        alg = md.new(name)
        ref = hashlib.new(name)
        for chunk in make_chunks(buf, 500):
            alg.update(chunk)
            ref.update(chunk)
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hashlib_buf(%s)" % name
        yield test


def test_check_against_hmac_nobuf():
    for name in md.algorithms_available:
        buf = _rnd(1024)
        key = _rnd(16)
        alg = md.new_hmac(key, buf, digestmod=name)
        ref = hmac.new(key, buf, digestmod=name)
        # Use partial to have the correct name in failed reports (by
        # avoiding late bindings).
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hmac_nobuf(%s)" % name
        yield test


def test_check_against_hmac_buf():
    for name in md.algorithms_available:
        buf = _rnd(4096)
        key = _rnd(16)
        alg = md.new_hmac(key, digestmod=name)
        ref = hmac.new(key, digestmod=name)
        for chunk in make_chunks(buf, 500):
            alg.update(chunk)
            ref.update(chunk)
        test = partial(assert_equal, alg.digest(), ref.digest())
        test.description = "check_against_hmac_buf(%s)" % name
        yield test


def test_instantiation():
    import inspect

    def check_instantiation(fun, name):
        alg1 = fun()
        alg2 = md.new(name)
        assert_equal(type(alg1), type(alg2))
        assert_equal(alg1.name, alg2.name)

    for name, member in inspect.getmembers(md):
        if name in md.algorithms_available:
            test = partial(check_instantiation, member, name)
            test.description = "check_instantiation(%s)" % name
            yield test
