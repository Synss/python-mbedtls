# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Blowfish cipher designed by Bruce Schneier in 1993."""

import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

from typing import Optional, Union

from mbedtls.exceptions import TLSError

from ._cipher import Cipher, Mode

__all__ = ["block_size", "key_size", "new"]

block_size: Final = 8
key_size: Final = None


def new(
    key: bytes,
    mode: Union[int, Literal[Mode.CBC, Mode.CFB, Mode.CTR, Mode.ECB]],
    iv: Optional[bytes] = None,
) -> Cipher:
    """Return a `Cipher` object that can perform Blowfish encryption and
    decryption.

    Blowfish cipher designed by Bruce Schneier in 1993.

    Parameters:
        key: The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode: The mode of operation of the cipher.
        iv: The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode_ = Mode(mode)
    key_len = len(key)
    if key_len not in range(4, 57):
        raise TLSError(msg="key size must be 4 to 56 bytes, got %i" % key_len)
    if mode_ not in {Mode.CBC, Mode.CFB, Mode.CTR, Mode.ECB}:
        raise TLSError(msg="unsupported mode %r" % mode_)
    name = (
        "BLOWFISH-%s%s" % (mode_.name, "64" if mode_ is Mode.CFB else "")
    ).encode("ascii")
    return Cipher(name, key, mode_, iv)
