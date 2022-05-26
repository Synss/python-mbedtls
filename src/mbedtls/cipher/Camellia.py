# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Camellia cipher developed by Japan's Mitsubishi an NTT in 2000."""


from mbedtls.exceptions import TLSError  # type: ignore

from ._cipher import Cipher, Mode

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
    mode = Mode(mode)
    if len(key) not in {16, 24, 32}:
        raise TLSError(
            msg="key size must 16, 24, or 32 bytes, got %r" % len(key)
        )
    if mode not in {Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR, Mode.GCM}:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = (
        "CAMELLIA-%i-%s%s"
        % (len(key) * 8, mode.name, "128" if mode is Mode.CFB else "")
    ).encode("ascii")
    return Cipher(name, key, mode, iv)
