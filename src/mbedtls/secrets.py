# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Generate secure random numbers.

This is an implementation of the PEP 506 API based on a
CSPRNG (Cryptographically Strong Pseudo Random Number Generator).

This module is compatibale with the standard `secrets` (PEP 506) module.

"""

import base64 as _base64
import binascii as _binascii

import mbedtls._random as _rnd

__all__ = [
    "randbits",
    "choice",
    "randbelow",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
]


DEFAULT_ENTROPY = 32


__rng = _rnd.default_rng()


randbits = __rng.getrandbits
choice = __rng.choice
randbelow = __rng.randbelow


def token_bytes(nbytes=None):
    """Return a random byte string containing `nbytes` number of bytes.

    If `nbytes` is ``None`` or not supplied, a reasonable default is used.

    """
    if nbytes is None:
        nbytes = DEFAULT_ENTROPY
    return __rng.urandom(nbytes)


def token_hex(nbytes=None):
    """Return a random text string, in hexadecimal."""
    return _binascii.hexlify(token_bytes(nbytes)).decode("ascii")


def token_urlsafe(nbytes=None):
    """Return a random URL-safe string."""
    tok = token_bytes(nbytes)
    return _base64.urlsafe_b64encode(tok).rstrip(b"=").decode("ascii")
