"""Unit tests for mbedtls.pk."""


from functools import partial

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal

import mbedtls.hash as hash
from mbedtls.pk._pk import _type_from_name
from mbedtls.pk import *

from . import _rnd


def fail_test(message):
    assert False, message
fail_test.__test__ = False


def test_cipher_list():
    assert len(CIPHER_NAME) == 5


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert tuple(cl) == CIPHER_NAME


def test_type_from_name():
    assert_equal(
        tuple(_type_from_name(name) for name in CIPHER_NAME),
        tuple(range(len(CIPHER_NAME))))


def get_ciphers():
    return (name for name in sorted(get_supported_ciphers())
            if name not in {b"NONE"})


def test_type_accessor():
    for name in get_ciphers():
        description = "test_type_accessor(%s)" % name
        cipher = CipherBase(name, digestmod=hash.md5)
        test = partial(assert_equal, cipher._type, _type_from_name(name))
        test.description = description
        yield test


def test_name_accessor():
    for name in get_ciphers():
        description = "test_name_accessor(%s)" % name
        cipher = CipherBase(name, digestmod=hash.md5)
        test = partial(assert_equal, cipher.name, name)
        test.description = description
        yield test


def test_key_size_accessor():
    for name in get_ciphers():
        description = "test_key_size_accessor(%s)" % name
        cipher = CipherBase(name, digestmod=hash.md5)
        test = partial(assert_equal, cipher.key_size, 0)
        test.description = description
        yield test


def test_digestmod():
    for name in get_ciphers():
        for md in hash.algorithms_available:
            md_alg = vars(hash)[md]
            assert isinstance(md, str)
            cipher = CipherBase(name, digestmod=md)
            test = partial(assert_equal, cipher._md_type, md_alg()._type)
            test.description = ("test_digestmod_from_string(%s:%s)" %
                                (name, md_alg.__name__))
            yield test


def test_digestmod_from_ctor():
    for name in get_ciphers():
        for md in hash.algorithms_available:
            md_alg = vars(hash)[md]
            assert callable(md_alg)
            cipher = CipherBase(name, digestmod=md_alg)
            test = partial(assert_equal, cipher._md_type, md_alg()._type)
            test.description = ("test_digestmod_from_ctor(%s:%s)" %
                                (name, md_alg.__name__))
            yield test


def test_rsa_encrypt_decrypt():
    for key_size in (1024, 2048, 4096):
        cipher = RSA(digestmod=hash.md5)
        cipher.generate(key_size)
        msg = _rnd(cipher.key_size - 11)
        enc = cipher.encrypt(msg)
        dec = cipher.decrypt(enc)
        test = partial(assert_equal, dec, msg)
        test.description = "test_encrypt_decrypt(%s:%s)" % ("RSA", key_size)
        yield test


class TestRsa:

    def setup(self):
        key_size = 2048
        self.cipher = RSA(digestmod=hash.md5)
        self.cipher.generate(key_size)

    def test_keypair(self):
        check_pair(self.cipher, self.cipher)

    def test_write_parse_private_key_der(self):
        key = self.cipher._write_private_key_der()
        prv = RSA(digestmod=hash.md5)
        prv._parse_private_key(key)
        check_pair(self.cipher, prv)

    def test_write_parse_private_key_pem(self):
        key = self.cipher._write_private_key_pem()
        prv = RSA(digestmod=hash.md5)
        prv._parse_private_key(key)
        check_pair(self.cipher, prv)

    def test_write_parse_public_key_der(self):
        key = self.cipher._write_public_key_der()
        pub = RSA(digestmod=hash.md5)
        pub._parse_public_key(key)
        check_pair(pub, self.cipher)

    def test_write_parse_public_key_pem(self):
        key = self.cipher._write_public_key_pem()
        pub = RSA(digestmod=hash.md5)
        pub._parse_public_key(key)
        check_pair(pub, self.cipher)
