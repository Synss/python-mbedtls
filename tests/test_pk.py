"""Unit tests for mbedtls.pk."""


from functools import partial

from nose.plugins.skip import SkipTest
from nose.tools import (assert_equal, assert_is_instance,
                        assert_true, assert_false,
                        assert_is_none, assert_is_not_none,
                        raises,
                        )

import mbedtls.hash as hash
from mbedtls.exceptions import *
from mbedtls.exceptions import _ErrorBase
from mbedtls.pk._pk import _type_from_name, _get_md_alg
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
        cipher = CipherBase(name)
        test = partial(assert_equal, cipher._type, _type_from_name(name))
        test.description = description
        yield test


def test_name_accessor():
    for name in get_ciphers():
        description = "test_name_accessor(%s)" % name
        cipher = CipherBase(name)
        test = partial(assert_equal, cipher.name, name)
        test.description = description
        yield test


def test_key_size_accessor():
    for name in get_ciphers():
        description = "test_key_size_accessor(%s)" % name
        cipher = CipherBase(name)
        test = partial(assert_equal, cipher.key_size, 0)
        test.description = description
        yield test


def test_digestmod():
    for name in hash.algorithms_available:
        alg = _get_md_alg(name)
        test = partial(assert_is_instance, alg(), hash.Hash)
        test.description = "test_digestmod_from_string(%s)" % name
        yield test


def test_digestmod_from_ctor():
    for name in hash.algorithms_available:
        md_alg = vars(hash)[name]
        assert callable(md_alg)
        alg = _get_md_alg(md_alg)
        test = partial(assert_is_instance, alg(), hash.Hash)
        test.description = "test_digestmod_from_ctor(%s)" % name
        yield test


def test_rsa_encrypt_decrypt():
    for key_size in (1024, 2048, 4096):
        cipher = RSA()
        cipher.generate(key_size)
        msg = _rnd(cipher.key_size - 11)
        enc = cipher.encrypt(msg)
        dec = cipher.decrypt(enc)
        test = partial(assert_equal, dec, msg)
        test.description = "test_encrypt_decrypt(%s:%s)" % ("RSA", key_size)
        yield test


def test_rsa_sign_without_key_returns_none():
    cipher = RSA()
    message = _rnd(4096)
    assert_is_none(cipher.sign(message, hash.md5))


class TestRsa:

    def setup(self):
        key_size = 2048
        self.cipher = RSA()
        self.cipher.generate(key_size)

    def test_keypair(self):
        assert_true(check_pair(self.cipher, self.cipher))

    def test_write_and_parse_private_key_der(self):
        prv = self.cipher._write_private_key_der()
        cipher = RSA()
        cipher._parse_private_key(prv)
        assert_true(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))  # Test public half.
        assert_true(check_pair(cipher, cipher))

    def test_write_and_parse_private_key_pem(self):
        prv = self.cipher._write_private_key_pem()
        cipher = RSA()
        cipher._parse_private_key(prv)
        assert_true(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))  # Test public half.
        assert_true(check_pair(cipher, cipher))

    def test_write_and_parse_public_key_der(self):
        pub = self.cipher._write_public_key_der()
        cipher = RSA()
        cipher._parse_public_key(pub)
        assert_false(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))   # Test public half.
        assert_false(check_pair(cipher, cipher))

    def test_write_and_parse_public_key_pem(self):
        pub = self.cipher._write_public_key_pem()
        cipher = RSA()
        cipher._parse_public_key(pub)
        assert_false(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))   # Test public half.
        assert_false(check_pair(cipher, cipher))

    @raises(PrivateKeyError)
    def test_write_public_der_in_private_raises(self):
        pub = self.cipher._write_public_key_der()
        cipher = RSA()
        cipher._parse_private_key(pub)

    @raises(_ErrorBase)
    def test_write_private_der_in_public_raises(self):
        prv = self.cipher._write_private_key_der()
        cipher = RSA()
        cipher._parse_public_key(prv)

    def test_import_public_key(self):
        cipher = RSA()
        cipher.import_(self.cipher._write_public_key_der())
        assert_false(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))   # Test public half.
        assert_false(check_pair(cipher, cipher))

    def test_import_private_key(self):
        cipher = RSA()
        cipher.import_(self.cipher._write_private_key_der())
        assert_true(check_pair(self.cipher, cipher))  # Test private half.
        assert_true(check_pair(cipher, self.cipher))  # Test public half.
        assert_true(check_pair(cipher, cipher))

    def test_sign_verify(self):
        message = _rnd(4096)
        sig = self.cipher.sign(message, hash.md5)
        assert_is_not_none(sig)
        assert_true(self.cipher.verify(message, sig, hash.md5))
        assert_false(self.cipher.verify(message + b"\0", sig, hash.md5))

    def test_sign_verify_default_digestmod(self):
        message = _rnd(4096)
        sig = self.cipher.sign(message)
        assert_is_not_none(sig)
        assert_true(self.cipher.verify(message, sig))
        assert_false(self.cipher.verify(message + b"\0", sig))
