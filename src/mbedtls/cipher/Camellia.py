# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Camellia cipher developed by Japan's Mitsubishi an NTT in 2000."""


import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

from typing import Optional, Union

from mbedtls.exceptions import TLSError

from ._cipher import Cipher, Mode

__all__ = ["block_size", "key_size", "new"]

block_size: Final = 16
key_size: Final = None


def new(
    key: bytes,
    mode: Union[
        int, Literal[Mode.CBC, Mode.CFB, Mode.CTR, Mode.ECB, Mode.GCM]
    ],
    iv: Optional[bytes] = None,
) -> Cipher:
    """Return a `Cipher` object that can perform Camellia encryption and
    decryption.

    Camellia cipher developed by Japan's Mitsubishi an NTT in 2000.

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
    if len(key) not in {16, 24, 32}:
        raise TLSError(
            msg="key size must 16, 24, or 32 bytes, got %r" % len(key)
        )
    if mode_ not in {Mode.CBC, Mode.CFB, Mode.CTR, Mode.ECB, Mode.GCM}:
        raise TLSError(msg="unsupported mode %r" % mode_)
    name = (
        "CAMELLIA-%i-%s%s"
        % (len(key) * 8, mode_.name, "128" if mode_ is Mode.CFB else "")
    ).encode("ascii")
    return Cipher(name, key, mode_, iv)
