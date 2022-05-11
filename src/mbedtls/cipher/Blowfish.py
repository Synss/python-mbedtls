# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Blowfish cipher designed by Bruce Schneier in 1993."""


from mbedtls.exceptions import TLSError  # type: ignore

from . import _cipher

__all__ = ["block_size", "key_size", "new"]

block_size = 8
key_size = None


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform Blowfish encryption and
    decryption.

    Blowfish cipher designed by Bruce Schneier in 1993.

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
    key_len = len(key)
    if key_len not in range(4, 57):
        raise TLSError(msg="key size must be 4 to 56 bytes, got %i" % key_len)
    if mode not in {
        _cipher.Mode.ECB,
        _cipher.Mode.CBC,
        _cipher.Mode.CFB,
        _cipher.Mode.CTR,
    }:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = (
        "BLOWFISH-%s%s" % (mode.name, "64" if mode is _cipher.Mode.CFB else "")
    ).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
