"""Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
at RSA Security."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport _cipher
import _cipher
from mbedtls.exceptions import *


def new(key, mode=None, iv=None):
    """Return a `Cipher` object that can perform ARC4 encryption and
    decryption.

    Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
    at RSA Security.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (None): The feedback mode is ignored for ARC4.
        iv (None): ARC4 does not use IV.

    """
    bitlength = len(key) * 8
    if bitlength not in {128}:
        raise InvalidKeyLengthError(
            "bitlength must be 128, got %r" % bitlength)
    name = ("ARC4-%i" % (bitlength,)).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
