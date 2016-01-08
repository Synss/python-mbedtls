"""Unit tests for mbedtls.cipher."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name

from functools import partial

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal, assert_raises
from nose.tools import raises

# pylint: disable=import-error
from mbedtls.cipher._cipher import *
from mbedtls.cipher._cipher import CIPHER_NAME, get_supported_ciphers
from mbedtls.cipher._cipher import Cipher
from mbedtls.exceptions import *

import mbedtls.cipher.AES as mb_AES
import mbedtls.cipher.ARC4 as mb_ARC4
import mbedtls.cipher.Blowfish as mb_Blowfish
import mbedtls.cipher.Camellia as mb_Camellia
import mbedtls.cipher.DES as mb_DES
import mbedtls.cipher.DES3 as mb_DES3
import mbedtls.cipher.DES3dbl as mb_DES3dbl
# pylint: enable=import-error

from . import _rnd


def test_cipher_list():
    assert len(CIPHER_NAME) == 49


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert cl and set(cl).issubset(set(CIPHER_NAME))


@raises(UnsupportedCipherError)
def test_wrong_size_raises_unsupported_cipher():
    Cipher(b"AES-512-ECB", b"", 0, b"")


@raises(UnsupportedCipherError)
def test_random_name_raises_unsupported_cipher():
    Cipher(b"RANDOM TEXT IS NOT A CIPHER", b"", 0, b"")


@raises(UnsupportedCipherError)
def test_zero_length_raises_unsupported_cipher():
    Cipher(b"", b"", 0, b"")


@raises(ValueError)
def test_cbc_raises_value_error_without_iv():
    Cipher(b"AES-512-CBC", b"", MODE_CBC, b"")


@raises(ValueError)
def test_cfb_raises_value_error_without_iv():
    Cipher(b"AES-512-CFB", b"", MODE_CFB, b"")


def setup_cipher(name):
    cipher = Cipher(name, key=None, mode=None, iv=b"\x00")
    key = _rnd(cipher.key_size)
    iv = _rnd(cipher.iv_size)
    block = _rnd(cipher.block_size)
    if name.startswith(b"AES"):
        mod = mb_AES
    elif name.startswith(b"ARC4"):
        mod = mb_ARC4
    elif name.startswith(b"BLOWFISH"):
        mod = mb_Blowfish
    elif name.startswith(b"CAMELLIA"):
        mod = mb_Camellia
    elif name.startswith(b"DES-EDE3"):
        mod = mb_DES3
    elif name.startswith(b"DES-EDE"):
        mod = mb_DES3dbl
    elif name.startswith(b"DES"):
        mod = mb_DES
    else:
        raise NotImplementedError
    return mod, key, cipher.mode, iv, block


def get_ciphers():
    return (name for name in sorted(get_supported_ciphers())
            if not name.endswith(b"CCM"))  # Not compiled by default.


def is_streaming(cipher):
    return cipher.name.startswith(b"ARC") or cipher.mode is not MODE_ECB


def skip_test(message):
    raise SkipTest(message)
skip_test.__test__ = False


def fail_test(message):
    assert False, message
fail_test.__test__ = False


def check_encrypt_decrypt(cipher, block):
    assert_equal(cipher.decrypt(cipher.encrypt(block)), block)


def test_encrypt_decrypt():
    for name in get_ciphers():
        description = "check_encrypt_decrypt(%s)" % name.decode()
        mod, key, mode, iv, block = setup_cipher(name)
        cipher = mod.new(key, mode, iv)
        test = partial(check_encrypt_decrypt, cipher, block)
        test.description = description
        yield test


def test_check_against_pycrypto():
    try:
        import Crypto.Cipher as pc
        # We must import the following to have them in scope.
        # pylint: disable=unused-import
        from Crypto.Cipher import AES
        from Crypto.Cipher import ARC4
        from Crypto.Cipher import Blowfish
        from Crypto.Cipher import DES
        from Crypto.Cipher import DES3
        # pylint: enable=unused-import
    except ImportError as exc:
        raise SkipTest(str(exc))

    pc_supported_modes = {
        MODE_ECB,
        MODE_CBC,
        MODE_CFB,
        MODE_CTR,
    }

    def check_against_pycrypto(cipher, ref, block):
        assert_equal(cipher.encrypt(block), ref.encrypt(block))

    for name in get_ciphers():
        description = "check_against_pycrypto(%s)" % name.decode()
        mod, key, mode, iv, block = setup_cipher(name)
        if mode not in pc_supported_modes.difference(
                {MODE_CTR, MODE_CFB}):
            # Counter actually requires the counter.
            skip_test.description = description
            yield skip_test, "encryption mode unsupported"
            continue

        cipher = mod.new(key, mode, iv)
        try:
            if name.startswith(b"AES"):
                ref = pc.AES.new(key, cipher.mode, iv)
            elif name.startswith(b"ARC4"):
                ref = pc.ARC4.new(key)
            elif name.startswith(b"BLOWFISH"):
                ref = pc.Blowfish.new(key, cipher.mode, iv)
            elif name.startswith(b"DES-EDE"):
                # Must precede DES.
                ref = pc.DES3.new(key, cipher.mode, iv)
            elif name.startswith(b"DES"):
                ref = pc.DES.new(key, cipher.mode, iv)
            else:
                skip_test.description = description
                yield skip_test, "%s not available in pyCrypto" % cipher
                continue
        except ValueError as exc:
            # Catch exceptions from pyCrypto.
            fail_test.description = description
            yield fail_test, str(exc)
            continue

        # Use partial to avoid late binding in report.
        if cipher.mode is MODE_CBC:
            # mbed TLS adds a block to CBC (probably due to padding) so
            # that pyCrypto returns one block less.
            test = partial(assert_equal, cipher.encrypt(block)[:len(block)],
                           ref.encrypt(block))
        else:
            test = partial(assert_equal, cipher.encrypt(block),
                           ref.encrypt(block))
        test.description = description
        yield test


def test_check_against_openssl():
    from binascii import hexlify
    from subprocess import PIPE, Popen

    CIPHER_LOOKUP = {
        b"AES-128-CFB128": "aes-128-cfb",
        b"AES-192-CFB128": "aes-192-cfb",
        b"AES-256-CFB128": "aes-256-cfb",
        b"CAMELLIA-128-CFB128": "camellia-128-cfb",
        b"CAMELLIA-192-CFB128": "camellia-192-cfb",
        b"CAMELLIA-256-CFB128": "camellia-256-cfb",
        b"BLOWFISH-ECB": "bf-ecb",
        b"BLOWFISH-CBC": "bf-cbc",
        b"BLOWFISH-CFB64": "bf-cfb",
        b"ARC4-128": "rc4",
    }

    for name in get_ciphers():
        description = "check_against_openssl(%s)" % name.decode()
        mod, key, mode, iv, block = setup_cipher(name)
        if mode == MODE_GCM:
            skip_test.description = description
            yield skip_test, "encryption mode unsupported"
            continue
        if name in {b"ARC4-128", b"DES-EDE3-ECB", b"DES-EDE-ECB",
                    b"CAMELLIA-256-ECB",
                    b"CAMELLIA-128-CTR", b"CAMELLIA-192-CTR",
                    b"CAMELLIA-256-CTR",
                    b"BLOWFISH-CTR",
                    }:
            yield skip_test, "%s not available in openssl" % name
            continue

        cipher = mod.new(key, mode, iv)
        openssl_cipher = CIPHER_LOOKUP.get(
            cipher.name, cipher.name.decode("ascii").lower())

        openssl = Popen(("openssl enc -%s -K %s -iv %s -nosalt" % (
            openssl_cipher,
            hexlify(key).decode("ascii"),
            hexlify(iv).decode("ascii")) +
            (" -nopad" if cipher.mode is MODE_ECB else "")
        ).split(),
            stdin=PIPE, stdout=PIPE, stderr=PIPE)
        out, err = openssl.communicate(input=block)
        if err:
            fail_test.description = description
            yield fail_test, ":".join((str(cipher), openssl_cipher,
                                       err.decode().splitlines()[0]))
            continue

        test = partial(assert_equal, cipher.encrypt(block), out)
        test.description = description
        yield test


def test_streaming_ciphers():
    for name in get_ciphers():
        description = "check_stream_cipher(%s)" % name.decode()
        mod, key, mode, iv, block = setup_cipher(name)
        cipher = mod.new(key, mode, iv)
        if is_streaming(cipher):
            block = _rnd(20000)
            check_encrypt_decrypt.description = description
            yield check_encrypt_decrypt, cipher, block


def test_fixed_block_size_ciphers():

    def check_encrypt_raises(cipher, block, exc):
        with assert_raises(exc):
            cipher.encrypt(block)

    for name in get_ciphers():
        mod, key, mode, iv, block = setup_cipher(name)
        cipher = mod.new(key, mode, iv)
        if not is_streaming(cipher):
            description = "long_block_raises(%s)" % name.decode()
            test = partial(check_encrypt_raises, cipher, block + _rnd(1),
                           FullBlockExpectedError)
            test.description = description
            yield test

            description = "short_block_raises(%s)" % name.decode()
            test = partial(check_encrypt_raises, cipher, block[1:],
                           FullBlockExpectedError)
            test.description = description
            yield test
