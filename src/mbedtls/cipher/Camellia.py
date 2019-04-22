"""Camellia cipher developed by Japan's Mitsubishi an NTT in 2000."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


from . import _cipher
from mbedtls.exceptions import *

__all__ = ["block_size", "key_size", "new"]

block_size = 16
key_size = None


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform Camellia encryption and
    decryption.

    Camellia cipher developed by Japan's Mitsubishi an NTT in 2000.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (Mode): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode = _cipher.Mode(mode)
    if len(key) not in {16, 24, 32}:
        raise TLSError(
            msg="key size must 16, 24, or 32 bytes, got %r" % len(key)
        )
    if mode not in {
        _cipher.Mode.ECB,
        _cipher.Mode.CBC,
        _cipher.Mode.CFB,
        _cipher.Mode.CTR,
        _cipher.Mode.GCM,
        _cipher.Mode.CCM,
    }:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = (
        "CAMELLIA-%i-%s%s"
        % (len(key) * 8, mode.name, "128" if mode is _cipher.Mode.CFB else "")
    ).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
