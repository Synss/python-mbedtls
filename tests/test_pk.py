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


def test_check_rsa_keypair():
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    check_pair(cipher, cipher)


def test_write_parse_private_key_der():
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    prv = RSA(digestmod=hash.md5)
    key = cipher._write_private_key_der()
    prv._parse_private_key(key)
    check_pair(cipher, prv)


def test_write_parse_private_key_pem():
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    prv = RSA(digestmod=hash.md5)
    key = cipher._write_private_key_pem()
    prv._parse_private_key(key)
    check_pair(cipher, prv)


def test_write_parse_private_key_pem_raise():
    raise SkipTest()
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    prv = RSA(digestmod=hash.md5)
    key = b"".join(cipher._write_private_key_pem().split(b"\n")[1:-1])
    prv._parse_private_key(key)
    check_pair(cipher, prv)


def test_write_parse_public_key_der():
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    pub = RSA(digestmod=hash.md5)
    key = cipher._write_public_key_der()
    pub._parse_public_key(key)
    check_pair(pub, cipher)


def test_write_parse_public_key_pem():
    key_size = 1024
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(key_size)
    pub = RSA(digestmod=hash.md5)
    key = cipher._write_public_key_pem()
    pub._parse_public_key(key)
    check_pair(pub, cipher)


def test_encrypt_decrypt_rsa():
    raise SkipTest()
    cipher = RSA(digestmod=hash.md5)
    cipher.generate(1024)
    block = _rnd(1024)
    test = partial(assert_equal(cipher.decrypt(cipher.encrypt(block)),
                                block))
    test.description = "check_encrypt_decrypt(%s)" % name.decode()
    yield test
