# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
at RSA Security."""

import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

from typing import Optional, Union

from mbedtls.exceptions import TLSError

from ._cipher import Cipher, Mode

__all__ = ["block_size", "key_size", "new"]

block_size: Final = 1
key_size: Final = 16


def new(
    key: bytes,
    mode: Optional[Union[int, Literal[Mode.STREAM]]] = None,
    iv: Optional[bytes] = None,
) -> Cipher:
    """Return a `Cipher` object that can perform ARC4 encryption and
    decryption.

    Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
    at RSA Security.

    Parameters:
        key: The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode: The feedback mode is ignored for ARC4.
        iv: ARC4 does not use IV.

    """
    if len(key) != key_size:
        raise TLSError(
            msg="key size must be %i bytes, got %i" % (key_size, len(key))
        )
    if mode not in {None, Mode.STREAM}:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = ("ARC4-%i" % (len(key) * 8)).encode("ascii")
    return Cipher(name, key, Mode.STREAM, iv)
