"""Salsa20 and the closely related ChaCha are stream ciphers developed by Daniel J. Bernstein.

"""

__author__ = "Stephen.Y"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


from . import _cipher
from mbedtls.exceptions import *

__all__ = ["block_size", "key_size", "new"]


block_size = 1
key_size = 32


def new(key, mode, iv=None, ad=None):
    """Return a `Cipher` object that can perform ChaCha20 encryption and
    decryption.

    ChaCha was created by Daniel Bernstein as a variant of
    its Salsa cipher https://cr.yp.to/chacha/chacha-20080128.pdf
    ChaCha20 is the variant with 20 rounds, that was also standardized
    in RFC 7539.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (Mode): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.
        ad (bytes or None): The associated data for ChaCha/Poly mode.

    """
    if len(key) != 32:
        raise TLSError(msg="key size must 32 bytes, got %r" % len(key))
    if mode == _cipher.Mode.STREAM:
        assert ad is None
        cipher = _cipher.Cipher(b"CHACHA20", key, mode, iv)
    elif mode == _cipher.Mode.CHACHAPOLY:
        ad = b"" if ad is None else ad
        cipher = _cipher.AEADCipher(b"CHACHA20-POLY1305", key, mode, iv, ad)
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    return cipher
