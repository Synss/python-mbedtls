"""Unit tests for mbedtls.cipher."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name

import random

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal
from nose.tools import raises

from Crypto.Cipher import AES as pcAES
from Crypto.Cipher import ARC4 as pcARC4
from Crypto.Cipher import Blowfish as pcBlowfish
from Crypto.Cipher import DES as pcDES

# pylint: disable=import-error
from mbedtls.cipher import *
# pylint: enable=import-error


def assert_canonical_repr(obj):
    # ``eval`` *must* run into the caller's environment, so let's get it from
    # the stack.
    from inspect import stack
    frame = stack()[1][0]
    try:
        # pylint: disable=eval-used
        newobj = eval(repr(obj), frame.f_globals, frame.f_locals)
    except TypeError:
        raise AssertionError("Cannot eval '%r'" % obj) from None
    finally:
        # explicitely delete the frame to avoid memory leaks, see also
        # https://docs.python.org/3/library/inspect.html#the-interpreter-stack
        del frame
    assert isinstance(newobj, type(obj))
assert_canonical_repr.__test__ = False


def _rnd(length):
    return bytes(random.randrange(0, 256) for _ in range(length))
_rnd.__test__ = False


class TestRnd:

    @staticmethod
    def test_key_length():
        for length in range(1024 + 1, 8):
            assert len(_rnd(length)) == length

    @staticmethod
    def test_values_fit_in_latin1():
        k = _rnd(2048)
        assert k.decode("latin1")


def test_cipher_list():
    assert len(CIPHER_NAME) == 49


def test_get_supported_ciphers():
    cl = get_supported_ciphers()
    assert cl and set(cl).issubset(set(CIPHER_NAME))


@raises(UnsupportedCipherError)
def test_wrong_size_raises_unsupported_cipher():
    Cipher(b"AES-512-ECB", b"", b"")


@raises(UnsupportedCipherError)
def test_random_name_raises_unsupported_cipher():
    Cipher(b"RANDOM TEXT IS NOT A CIPHER", b"", b"")


@raises(UnsupportedCipherError)
def test_zero_length_raises_unsupported_cipher():
    Cipher(b"", b"", b"")


class _TestCipherBase:

    """Test functions common to all ciphers."""

    def __init__(self, name):
        self.name = name
        self.operation = -1
        self.block_size = 0
        self.iv_size = 0
        self.key_size = 0
        self.cls = Cipher

    def setup(self):
        self.block = _rnd(self.block_size)
        self.iv = _rnd(self.iv_size)
        self.key = _rnd(self.key_size)
        self.cipher = self.cls(self.name, self.key, self.iv)

    def test_repr(self):
        assert_canonical_repr(self.cipher)

    def test_block_size_accessor(self):
        assert_equal(self.cipher.block_size, self.block_size)

    def test_iv_size_accessor(self):
        assert_equal(self.cipher.iv_size, self.iv_size)

    def test_key_size_accessor(self):
        assert_equal(self.cipher.key_size, self.key_size)

    def test_name_accessor(self):
        assert_equal(self.cipher.name, self.name)

    def test_operation_accessor(self):
        assert_equal(self.cipher._operation, self.operation)

    def test_encrypt_decrypt(self):
        message = _rnd(self.block_size * 8)
        assert_equal(self.cipher.decrypt(self.cipher.encrypt(message)),
                     message)

    def test_set_enc_key(self):
        self.cipher._set_enc_key(self.key)
        assert self.cipher._operation == OP_ENCRYPT

    def test_set_dec_key(self):
        self.cipher._set_dec_key(self.key)
        assert self.cipher._operation == OP_DECRYPT

    @raises(BadInputDataError)
    def test_long_enc_key_raises(self):
        self.cipher._set_enc_key(self.key + b"\x00")

    @raises(BadInputDataError)
    def test_short_enc_key_raises(self):
        self.cipher._set_enc_key(self.key[1:])

    @raises(BadInputDataError)
    def test_long_dec_key_raises(self):
        self.cipher._set_dec_key(self.key + b"\x00")

    @raises(BadInputDataError)
    def test_short_dec_key_raises(self):
        self.cipher._set_dec_key(self.key[1:])

    def test_set_iv(self):
        self.cipher._set_iv(self.iv)

    @raises(FeatureUnavailableError)
    def test_long_iv_raises(self):
        self.cipher._set_iv(self.iv + b"\x00")

    @raises(BadInputDataError)
    def test_short_iv_raises(self):
        self.cipher._set_iv(self.iv[1:])

    def test_update(self):
        self.cipher._set_iv(self.iv)
        self.cipher._set_enc_key(self.key)
        enc = self.cipher._update(self.block)
        self.cipher._set_dec_key(self.key)
        dec = self.cipher._update(enc)
        assert dec == self.block

    @raises(FullBlockExpectedError)
    def test_long_block_raises(self):
        self.cipher._set_enc_key(self.key)
        self.cipher._update(self.block + b"\x00")

    @raises(FullBlockExpectedError)
    def test_short_block_raises(self):
        self.cipher._set_enc_key(self.key)
        self.cipher._update(self.block[1:])

    def test_crypt(self):
        self.cipher._set_enc_key(self.key)
        enc = self.cipher._crypt(self.iv, self.block)
        self.cipher._set_dec_key(self.key)
        dec = self.cipher._crypt(self.iv, enc)
        assert dec == self.block

    @raises(FullBlockExpectedError)
    def test_long_crypt_raises(self):
        self.cipher._set_enc_key(self.key)
        self.cipher._crypt(self.iv, self.block + b"\x00")

    @raises(FullBlockExpectedError)
    def test_short_crypt_raises(self):
        self.cipher._set_enc_key(self.key)
        self.cipher._crypt(self.iv, self.block[1:])


class _Test_Aes(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name)
        self.operation = 0
        self.block_size = 16
        self.iv_size = 16
        self.cls = Aes


class Test_Aes_128_ECB(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-128-ECB")
        self.key_size = 128 // 8

    def test_check_against_pycrypto(self):
        self.cipher._set_enc_key(self.key)
        cipher = pcAES.new(self.key, pcAES.MODE_ECB, self.iv)
        assert_equal(self.cipher._crypt(self.iv, self.block),
                     cipher.encrypt(self.block))


class Test_Aes_192_ECB(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-192-ECB")
        self.key_size = 192 // 8


class Test_Aes_256_ECB(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-256-ECB")
        self.key_size = 256 // 8


class Test_Camellia_128_ECB(_TestCipherBase):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-ECB")
        self.operation = 0
        self.block_size = 16
        self.iv_size = 16
        self.key_size = 128 // 8
        self.cls = Camellia


class Test_Des_ECB(_TestCipherBase):

    def __init__(self):
        super().__init__(b"DES-ECB")
        self.operation = 0
        self.block_size = 8
        self.iv_size = 8
        self.key_size = 64 // 8
        self.cls = Des

    def test_long_iv_raises(self):
        # IV is ignored for ECB.
        raise SkipTest("test invalid in this context")

    def test_check_against_pycrypto(self):
        self.cipher._set_enc_key(self.key)
        cipher = pcDES.new(self.key, pcDES.MODE_ECB, self.iv)
        assert_equal(self.cipher._crypt(self.iv, self.block),
                     cipher.encrypt(self.block))


class Test_Blowfish_ECB(_TestCipherBase):

    def __init__(self):
        super().__init__(b"BLOWFISH-ECB")
        self.operation = 0
        self.block_size = 8
        self.iv_size = 8
        self.key_size = 128 // 8
        self.cls = Blowfish

    @raises(InvalidKeyLengthError)
    def test_long_dec_key_raises(self):
        key = _rnd(1024)
        self.cipher._set_enc_key(key)

    @raises(InvalidKeyLengthError)
    def test_long_enc_key_raises(self):
        key = _rnd(1024)
        self.cipher._set_dec_key(key)

    def test_short_dec_key_raises(self):
        raise SkipTest("test invalid in this context")

    def test_short_enc_key_raises(self):
        raise SkipTest("test invalid in this context")

    def test_long_iv_raises(self):
        # IV is ignored for ECB.
        raise SkipTest("test invalid in this context")

    def test_crypt_with_short_key(self):
        key = _rnd(32 // 8)  # The shortest possible key.
        enc = self.cipher._crypt(self.iv, self.block)
        self.cipher._set_dec_key(key)
        dec = self.cipher._crypt(self.iv, enc)
        assert dec == self.block

    def test_crypt_with_long_key(self):
        key = _rnd(448 // 8)  # The longest possible key.
        enc = self.cipher._crypt(self.iv, self.block)
        self.cipher._set_dec_key(key)
        dec = self.cipher._crypt(self.iv, enc)
        assert dec == self.block

    def test_check_against_pycrypto(self):
        self.cipher._set_enc_key(self.key)
        cipher = pcBlowfish.new(self.key, pcBlowfish.MODE_ECB, self.iv)
        assert_equal(self.cipher._crypt(self.iv, self.block),
                     cipher.encrypt(self.block))


class Test_Arc4_128(_TestCipherBase):

    def __init__(self):
        super().__init__(b"ARC4-128")
        self.operation = 0
        self.block_size = 1
        self.iv_size = 0
        self.key_size = 128 // 8
        self.cls = Arc4

    def test_long_iv_raises(self):
        raise SkipTest("test invalid in this context")

    def test_short_iv_raises(self):
        raise SkipTest("test invalid in this context")

    def test_short_block_raises(self):
        raise SkipTest("test invalid in this context")

    def test_long_block_raises(self):
        raise SkipTest("test invalid in this context")

    def test_long_update(self):
        block = _rnd(1024)
        self.cipher._set_iv(self.iv)
        self.cipher._set_enc_key(self.key)
        enc = self.cipher._update(block)
        self.cipher._set_dec_key(self.key)
        dec = self.cipher._update(enc)
        assert dec == block

    def test_short_crypt_raises(self):
        raise SkipTest("test invalid in this context")

    def test_long_crypt_raises(self):
        raise SkipTest("test invalid in this context")

    def test_long_crypt(self):
        block = _rnd(1024)
        self.cipher._set_enc_key(self.key)
        enc = self.cipher._crypt(self.iv, block)
        self.cipher._set_dec_key(self.key)
        dec = self.cipher._crypt(self.iv, enc)
        assert dec == block

    def test_check_against_pycrypto(self):
        self.cipher._set_enc_key(self.key)
        cipher = pcARC4.new(self.key)
        assert_equal(self.cipher._crypt(self.iv, self.block),
                     cipher.encrypt(self.block))
