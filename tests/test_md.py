"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from functools import partial
import hashlib
import hmac

from nose.tools import assert_equal

# pylint: disable=import-error
from mbedtls.md import *
from mbedtls.md import MD_NAME, get_supported_mds, MessageDigest
# pylint: enable=import-error

from . import _rnd


def available_mds():
    return get_supported_mds()


def test_md_list():
    assert len(MD_NAME) == 10


def test_get_supported_mds():
    mds = available_mds()
    assert mds and mds.issubset(set(MD_NAME))


def test_digest_file():
    md5 = Md5()
    ref = hashlib.md5()
    with open(__file__, mode="r") as file:
        for line in file:
            ref.update(line.encode("ascii"))
    assert_equal(md5.digest_file(__file__), ref.digest())


def test_digest_hmac():
    md5 = Md5()
    msg = _rnd(1024)
    key = _rnd(16)
    ref = hmac.new(key, msg, digestmod="MD5")
    assert_equal(md5.digest_hmac(key, msg), ref.digest())


def test_check_against_hashlib():
    for name in available_mds():
        msg = _rnd(1024)
        md = MessageDigest(name)
        ref = hashlib.new(name.decode("ascii"))
        ref.update(msg)
        # Use partial to have the correct name in failed reports (by
        # avoiding late bindings).
        test = partial(assert_equal, md.digest(msg), ref.digest())
        test.description = "check_against_hashlib(%s)" % name.decode("ascii")
        yield test


def test_instantiation():
    import inspect
    import mbedtls.md

    def isdigest(cls):
        return (inspect.isclass(cls) and
                cls is not MessageDigest and
                issubclass(cls, MessageDigest))

    for name, cls in inspect.getmembers(mbedtls.md, predicate=isdigest):
        cls.description = "check_instantiation(%s)" % name
        yield cls
