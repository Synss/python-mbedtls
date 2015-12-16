"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
import hashlib
import hmac

from nose.tools import assert_equal

# pylint: disable=import-error
from mbedtls.md import *
from mbedtls.md import MD_NAME, get_supported_mds
# pylint: enable=import-error

from . import _rnd


def test_md_list():
    assert len(MD_NAME) == 10


def test_get_supported_mds():
    mdl = get_supported_mds()
    assert mdl and set(mdl).issubset(set(MD_NAME))


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


class _TestDigestBase:

    def __init__(self, md_cls):
        self.cls = md_cls

    def setup(self):
        self.md = self.cls()

    def test_check_against_reference_impl(self):
        msg = _rnd(1024)
        ref = hashlib.new(str(self.md))
        ref.update(msg)
        assert_equal(self.md.digest(msg), ref.digest())


class Test_MD5(_TestDigestBase):

    def __init__(self):
        super().__init__(Md5)


class Test_SHA1(_TestDigestBase):

    def __init__(self):
        super().__init__(Sha1)


class Test_SHA224(_TestDigestBase):

    def __init__(self):
        super().__init__(Sha224)


class Test_SHA256(_TestDigestBase):

    def __init__(self):
        super().__init__(Sha256)


class Test_SHA384(_TestDigestBase):

    def __init__(self):
        super().__init__(Sha384)


class Test_SHA512(_TestDigestBase):

    def __init__(self):
        super().__init__(Sha512)


class Test_Ripemd160(_TestDigestBase):

    def __init__(self):
        super().__init__(Ripemd160)
