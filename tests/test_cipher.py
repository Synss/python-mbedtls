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

    def __init__(self, name, cipher):
        self.name = name
        self.cls = cipher

    def setup(self):
        _cipher = self.cls(self.name, None, None)
        self.block = _rnd(_cipher.block_size)
        self.iv = _rnd(_cipher.iv_size)
        self.key = _rnd(_cipher.key_size)
        self.cipher = self.cls(self.name, self.key, self.iv)

    def test_encrypt_decrypt(self):
        assert_equal(self.cipher.decrypt(self.cipher.encrypt(self.block)),
                     self.block)


class _Test_FixedKeyLength_Mixin:

    @raises(BadInputDataError)
    def test_long_enc_key_raises(self):
        self.cls(self.name, self.key + _rnd(1), self.iv)

    @raises(BadInputDataError)
    def test_short_enc_key_raises(self):
        self.cls(self.name, self.key[1:], self.iv)


class _Test_FixedIvLength_Mixin:
    # IV is ignored in ECB and CTR modes.

    @raises(FeatureUnavailableError)
    def test_long_iv_raises(self):
        self.cls(self.name, self.key, self.iv + b"\x00")

    @raises(BadInputDataError)
    def test_short_iv_raises(self):
        if not self.iv_size <= 1:
            raise SkipTest("test invalid in this context")
        self.cls(self.name, self.key, self.iv[1:])


class _Test_FixedBlockLength_Mixin:

    @raises(FullBlockExpectedError)
    def test_long_block_raises(self):
        self.cipher.encrypt(self.block + b"\x00")

    @raises(FullBlockExpectedError)
    def test_short_block_raises(self):
        self.cipher.encrypt(self.block[1:])


class _Test_VariableBlockLength_Mixin:

    def test_long_block(self):
        block = self.block + _rnd(1)
        enc = self.cipher.encrypt(block)
        dec = self.cipher.decrypt(enc)
        assert_equal(dec, block)

    def test_short_block(self):
        block = self.block[1:]
        enc = self.cipher.encrypt(block)
        dec = self.cipher.decrypt(enc)
        assert_equal(dec, block)


class _Test_Aes(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name, cipher=Aes)


class Test_Aes_128_ECB(_Test_Aes,
                       _Test_FixedKeyLength_Mixin,
                       _Test_FixedBlockLength_Mixin,
                       ):

    def __init__(self):
        super().__init__(b"AES-128-ECB")

    def test_check_against_pycrypto(self):
        cipher = pcAES.new(self.key, pcAES.MODE_ECB, self.iv)
        assert_equal(self.cipher.encrypt(self.block),
                     cipher.encrypt(self.block))


class Test_Aes_192_ECB(_Test_Aes,
                       _Test_FixedKeyLength_Mixin,
                       _Test_FixedBlockLength_Mixin,
                       ):

    def __init__(self):
        super().__init__(b"AES-192-ECB")


class Test_Aes_256_ECB(_Test_Aes,
                       _Test_FixedKeyLength_Mixin,
                       _Test_FixedBlockLength_Mixin,
                       ):

    def __init__(self):
        super().__init__(b"AES-256-ECB")


class Test_Aes_128_CBC(_Test_Aes,
                       _Test_FixedKeyLength_Mixin,
                       _Test_VariableBlockLength_Mixin,
                       ):

    def __init__(self):
        super().__init__(b"AES-128-CBC")


class Test_Aes_128_CFB128(_Test_Aes,
                          ):

    def __init__(self):
        super().__init__(b"AES-128-CFB128")


class Test_Aes_128_CTR(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-128-CTR")


class Test_Aes_128_GCM(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-128-GCM")

    # We test the accessors here as all three expected values
    # are different.

    def test_block_size_accessor(self):
        assert_equal(self.cipher.block_size, 16)

    def test_iv_size_accessor(self):
        assert_equal(self.cipher.iv_size, 12)

    def test_key_size_accessor(self):
        assert_equal(self.cipher.key_size, 128 // 8)

    def test_name_accessor(self):
        assert_equal(self.cipher.name, self.name)


class Test_Aes_128_CCM(_Test_Aes):

    def __init__(self):
        super().__init__(b"AES-128-GCM")


class _Test_Camellia(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name, cipher=Camellia)


class Test_Camellia_128_ECB(_Test_Camellia):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-ECB")


class Test_Camellia_128_CBC(_Test_Camellia):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-CBC")


class Test_Camellia_128_CFB128(_Test_Camellia):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-CFB128")


class Test_Camellia_128_CTR(_Test_Camellia):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-CTR")


class _Test_Camellia_128_GCM(_Test_Camellia):

    def __init__(self):
        super().__init__(b"CAMELLIA-128-GCM")


class _Test_Des(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name, Des)


class Test_Des_ECB(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-ECB")

    def test_check_against_pycrypto(self):
        cipher = pcDES.new(self.key, pcDES.MODE_ECB, self.iv)
        assert_equal(self.cipher.encrypt(self.block),
                     cipher.encrypt(self.block))


class Test_Des_CBC(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-CBC")


class Test_Des_EDE_ECB(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-EDE-ECB")


class Test_Des_EDE_CBC(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-EDE-CBC")


class Test_Des_EDE3_ECB(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-EDE3-ECB")


class Test_Des_EDE3_CBC(_Test_Des):

    def __init__(self):
        super().__init__(b"DES-EDE3-CBC")


class _Test_Blowfish(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name, cipher=Blowfish)

    @raises(InvalidKeyLengthError)
    def test_long_key_raises(self):
        key = _rnd(1024)
        cipher = self.cls(self.name, key, self.iv)
        cipher.decrypt(self.block)

    @raises(InvalidKeyLengthError)
    def test_short_key_raises(self):
        key = _rnd(32 // 8 - 1)
        cipher = self.cls(self.name, key, self.iv)
        cipher.encrypt(self.block)

    def test_short_key(self):
        key = _rnd(32 // 8)  # The shortest possible key.
        cipher = self.cls(self.name, key, self.iv)
        enc = cipher.encrypt(self.block)
        dec = cipher.decrypt(enc)
        assert dec == self.block

    def test_long_key(self):
        key = _rnd(448 // 8)  # The longest possible key.
        cipher = self.cls(self.name, key, self.iv)
        enc = cipher.encrypt(self.block)
        dec = cipher.decrypt(enc)
        assert dec == self.block


class Test_Blowfish_ECB(_Test_Blowfish):

    def __init__(self):
        super().__init__(b"BLOWFISH-ECB")

    def test_check_against_pycrypto(self):
        cipher = pcBlowfish.new(self.key, pcBlowfish.MODE_ECB, self.iv)
        assert_equal(self.cipher.encrypt(self.block),
                     cipher.encrypt(self.block))


class Test_Blowfish_CBC(_Test_Blowfish):

    def __init__(self):
        super().__init__(b"BLOWFISH-CBC")


class Test_Blowfish_CFB64(_Test_Blowfish):

    def __init__(self):
        super().__init__(b"BLOWFISH-CFB64")


class Test_Blowfish_CTR(_Test_Blowfish):

    def __init__(self):
        super().__init__(b"BLOWFISH-CTR")


class _Test_Arc4(_TestCipherBase):

    def __init__(self, name):
        super().__init__(name, cipher=Arc4)

    @raises(InvalidKeyLengthError)
    def test_long_key_raises(self):
        key = _rnd(2048 // 8 + 1)
        cipher = self.cls(self.name, key, self.iv)
        cipher.decrypt(self.block)

    @raises(InvalidKeyLengthError)
    def test_short_key_raises(self):
        key = _rnd(40 // 8 - 1)
        cipher = self.cls(self.name, key, self.iv)
        cipher.encrypt(self.block)

    def test_short_key(self):
        key = _rnd(40 // 8)  # The shortest possible key.
        cipher = self.cls(self.name, key, self.iv)
        enc = cipher.encrypt(self.block)
        dec = cipher.decrypt(enc)
        assert dec == self.block

    def test_long_key(self):
        key = _rnd(2048 // 8)  # The longest possible key.
        cipher = self.cls(self.name, key, self.iv)
        enc = cipher.encrypt(self.block)
        dec = cipher.decrypt(enc)
        assert dec == self.block

    def test_long_block(self):
        block = _rnd(1024)
        enc = self.cipher.encrypt(block)
        dec = self.cipher.decrypt(enc)
        assert dec == block


class Test_Arc4_128(_TestCipherBase):

    def __init__(self):
        super().__init__(b"ARC4-128", Arc4)

    def test_check_against_pycrypto(self):
        cipher = pcARC4.new(self.key)
        assert_equal(self.cipher.encrypt(self.block),
                     cipher.encrypt(self.block))
