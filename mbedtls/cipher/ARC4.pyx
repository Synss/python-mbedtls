"""Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
at RSA Security."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport _cipher
import _cipher
from mbedtls.exceptions import *


class Arc4(_cipher.Cipher):

    """Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
    at RSA Security.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (None): The feedback mode is ignored for ARC4.
        iv (None): ARC4 does not use IV.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, key, mode=None, iv=None):
        bitlength = len(key) * 8
        if bitlength not in {128}:
            raise InvalidKeyLengthError(
                "bitlength must be 128, got %r" % bitlength)
        name = ("ARC4-%i" % (bitlength,)).encode("ascii")
        super().__init__(name, key, iv)
