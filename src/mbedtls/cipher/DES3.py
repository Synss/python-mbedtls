# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Three-key triple DES cipher (also known as DES3, 3DES,
Triple DES, or DES-EDE3)."""


from mbedtls.exceptions import TLSError  # type: ignore

from ._cipher import Cipher, Mode

__all__ = ["block_size", "key_size", "new"]


block_size = 8
key_size = 24


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform three-key triple DES
    encryption and decryption.

    Three-key triple DES cipher (also known as DES3, 3DES,
    Triple DES, or DES-EDE3).

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
    if len(key) != key_size:
        raise TLSError(
            msg="key size must be %i bytes, got %i" % (key_size, len(key))
        )
    if mode not in {Mode.ECB, Mode.CBC}:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = ("DES-EDE3-%s" % mode.name).encode("ascii")
    return Cipher(name, key, mode, iv)
