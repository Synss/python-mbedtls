"""Unit tests for mbedtls.cipher."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name, redefined-outer-name

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


def test_wrong_size_raises_exception():
    with pytest.raises(TLSError):
        Cipher(b"AES-512-ECB", b"", 0, b"")


def test_random_name_raises_exception():
    with pytest.raises(TLSError):
        Cipher(b"RANDOM TEXT IS NOT A CIPHER", b"", 0, b"")


def test_zero_length_raises_exception():
    with pytest.raises(TLSError):
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


def test_wrong_key_size_raises_exception(cipher, randbytes):
    mod = module_from_name(cipher.name)
    if mod.key_size is None:
        pytest.skip("module defines variable-length key")
    with pytest.raises(TLSError):
        mod.new(randbytes(cipher.key_size) + b"\x00",
                cipher.mode, randbytes(cipher.iv_size))


def test_streaming_ciphers(cipher, randbytes):
    if not is_streaming(cipher):
        pytest.skip("not a streaming cipher")
    block = randbytes(20000)
    assert cipher.decrypt(cipher.encrypt(block)) == block


def test_fixed_block_size_ciphers_long_block_raise_exception(
        cipher, randbytes):
    if is_streaming(cipher):
        pytest.skip("streaming cipher")
    with pytest.raises(TLSError):
        block = randbytes(cipher.block_size) + randbytes(1)
        cipher.encrypt(block)


def test_fixed_block_size_ciphers_short_block_raise_exception(
        cipher, randbytes):
    if is_streaming(cipher):
        pytest.skip("streaming cipher")
    with pytest.raises(TLSError):
        block = randbytes(cipher.block_size)[1:]
        cipher.encrypt(block)
