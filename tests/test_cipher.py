"""Unit tests for mbedtls.cipher."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name, redefined-outer-name

from collections import namedtuple
from functools import partial

import pytest

# pylint: disable=import-error
from mbedtls.cipher._cipher import *
from mbedtls.cipher._cipher import CIPHER_NAME, get_supported_ciphers
from mbedtls.cipher._cipher import Cipher
from mbedtls.exceptions import *

import mbedtls.cipher as mb
# pylint: enable=import-error


def test_cipher_list():
    assert len(CIPHER_NAME) == 49


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert cl and set(cl).issubset(set(CIPHER_NAME))


def test_wrong_size_raises_cipher_error():
    with pytest.raises(CipherError):
        Cipher(b"AES-512-ECB", b"", 0, b"")


def test_random_name_raises_cipher_error():
    with pytest.raises(CipherError):
        Cipher(b"RANDOM TEXT IS NOT A CIPHER", b"", 0, b"")


def test_zero_length_raises_cipher_error():
    with pytest.raises(CipherError):
        Cipher(b"", b"", 0, b"")


def test_cbc_raises_value_error_without_iv():
    with pytest.raises(ValueError):
        Cipher(b"AES-512-CBC", b"", MODE_CBC, b"")


def test_cfb_raises_value_error_without_iv():
    with pytest.raises(ValueError):
        Cipher(b"AES-512-CFB", b"", MODE_CFB, b"")


def module_from_name(name):
    for cipher, mod in (
            (b"AES", mb.AES),
            (b"ARC4", mb.ARC4),
            (b"BLOWFISH", mb.Blowfish),
            (b"CAMELLIA", mb.Camellia),
            (b"DES-EDE3", mb.DES3),
            (b"DES-EDE", mb.DES3dbl),
            (b"DES", mb.DES)):
        if name.startswith(cipher):
            return mod
    raise NotImplementedError


@pytest.fixture(params=(name for name in sorted(get_supported_ciphers())
                        if not name.endswith(b"CCM")))  # Not compiled by default.
def cipher(request, randbytes):
    name = request.param
    cipher = Cipher(name, key=None, mode=None, iv=b"\x00")
    key = randbytes(cipher.key_size)
    iv = randbytes(cipher.iv_size)
    return module_from_name(name).new(key, cipher.mode, iv)


def is_streaming(cipher):
    return cipher.name.startswith(b"ARC") or cipher.mode is not MODE_ECB


def test_encrypt_decrypt(cipher, randbytes):
    block = randbytes(cipher.block_size)
    assert cipher.decrypt(cipher.encrypt(block)) == block


def test_module_level_block_size_variable(cipher):
    mod = module_from_name(cipher.name)
    assert cipher.block_size == mod.block_size


def test_module_level_key_size_variable(cipher):
    mod = module_from_name(cipher.name)
    if mod.key_size is None:
        pytest.skip("module defines variable-length key")
    assert cipher.key_size == mod.key_size


def test_wrong_key_size_raises_invalid_key_size_error(cipher, randbytes):
    mod = module_from_name(cipher.name)
    if mod.key_size is None:
        pytest.skip("module defines variable-length key")
    with pytest.raises(InvalidKeyLengthError):
        mod.new(randbytes(cipher.key_size) + b"\x00",
                cipher.mode, randbytes(cipher.iv_size))


def test_check_against_pycrypto(cipher, randbytes):
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
        pytest.skip(str(exc))

    pc_supported_modes = {
        MODE_ECB,
        MODE_CBC,
        MODE_CFB,
        MODE_CTR,
    }

    mod = module_from_name(cipher.name)
    if cipher.mode not in pc_supported_modes.difference(
            {MODE_CTR, MODE_CFB}):
        # Counter actually requires the counter.
        pytest.skip("encryption mode unsupported")

    key = randbytes(cipher.key_size)
    iv = randbytes(cipher.iv_size)
    block = randbytes(cipher.block_size)

    cipher = mod.new(key, cipher.mode, iv)   # A new cipher...
    try:
        ref = {
            mb.AES: pc.AES,
            mb.ARC4: pc.ARC4,
            mb.Blowfish: pc.Blowfish,
            mb.DES: pc.DES,
            mb.DES3: pc.DES3,
        }[mod].new(key, cipher.mode, iv)
    except KeyError:
        pytest.skip("%s not available in pyCrypto" % cipher)

    # Use partial to avoid late binding in report.
    if cipher.mode is MODE_CBC:
        # mbed TLS adds a block to CBC (probably due to padding) so
        # that pyCrypto returns one block less.
        assert cipher.encrypt(block)[:len(block)] == ref.encrypt(block)
    else:
        assert cipher.encrypt(block) == ref.encrypt(block)


@pytest.mark.skip
def test_check_against_openssl(cipher, randbytes):
    from binascii import hexlify
    from subprocess import PIPE, Popen

    if cipher.mode is MODE_GCM:
        pytest.skip("encryption mode unsupported")

    if cipher.name in {
        b"ARC4-128", b"DES-EDE3-ECB", b"DES-EDE-ECB",
        b"CAMELLIA-256-ECB",
        b"CAMELLIA-128-CTR", b"CAMELLIA-192-CTR",
        b"CAMELLIA-256-CTR",
        b"BLOWFISH-CTR",
    }:
        pytest.skip("not available in openssl")

    key = randbytes(cipher.key_size)
    iv = randbytes(cipher.iv_size)
    block = randbytes(cipher.block_size)

    # A new cipher...
    cipher = module_from_name(cipher.name).new(key, cipher.mode, iv)

    openssl_cipher = {
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
    }.get(cipher.name, cipher.name.decode("ascii").lower())

    cmd = ["openssl", "enc", "-%s" % openssl_cipher, "-nosalt",
           "-K", hexlify(key).decode("ascii")]
    if cipher.mode is MODE_ECB:
        cmd.append("-nopad")
    else:
        cmd.extend(["-iv", hexlify(iv).decode("ascii")])
    openssl = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = openssl.communicate(input=block)
    if err:
        pytest.fail(":".join((str(cipher), openssl_cipher,
                              err.decode().splitlines()[0])))
    else:
        assert cipher.encrypt(block) == out


def test_streaming_ciphers(cipher, randbytes):
    if not is_streaming(cipher):
        pytest.skip("not a streaming cipher")
    block = randbytes(20000)
    assert cipher.decrypt(cipher.encrypt(block)) == block


def test_fixed_block_size_ciphers_long_block_raise_ciphererror(
        cipher, randbytes):
    if is_streaming(cipher):
        pytest.skip("streaming cipher")
    with pytest.raises(CipherError):
        block = randbytes(cipher.block_size) + randbytes(1)
        cipher.encrypt(block)


def test_fixed_block_size_ciphers_short_block_raise_ciphererror(
        cipher, randbytes):
    if is_streaming(cipher):
        pytest.skip("streaming cipher")
    with pytest.raises(CipherError):
        block = randbytes(cipher.block_size)[1:]
        cipher.encrypt(block)
