"""Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
at RSA Security."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport mbedtls.cipher._cipher as _cipher
import mbedtls.cipher._cipher as _cipher
from mbedtls.exceptions import *


block_size = 1
key_size = 16


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
    if len(key) != key_size:
        raise TLSError(
            msg="key size must be %i bytes, got %i" % (key_size, len(key)))
    name = ("ARC4-%i" % (len(key) * 8)).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
