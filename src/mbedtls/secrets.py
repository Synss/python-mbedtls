# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Generate secure random numbers.

This is an implementation of the PEP 506 API based on a
CSPRNG (Cryptographically Strong Pseudo Random Number Generator).

This module is compatibale with the standard `secrets` (PEP 506) module.

"""

import base64 as _base64
import binascii as _binascii
import sys
from typing import Callable, Sequence, TypeVar, cast

import mbedtls._random as _rnd  # type: ignore

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final


__all__ = [
    "randbits",
    "choice",
    "randbelow",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
]


DEFAULT_ENTROPY: Final = 32


__rng = _rnd.default_rng()


randbits: Callable[[int], int] = __rng.getrandbits

T = TypeVar("T", covariant=True)
choice: Callable[[Sequence[T]], T] = __rng.choice
randbelow: Callable[[int], int] = __rng.randbelow


def token_bytes(nbytes: int = DEFAULT_ENTROPY) -> bytes:
    """Return a random byte string containing `nbytes` number of bytes.

    If `nbytes` is ``None`` or not supplied, a reasonable default is used.

    """
    return cast(bytes, __rng.urandom(nbytes))


def token_hex(nbytes: int = DEFAULT_ENTROPY) -> str:
    """Return a random text string, in hexadecimal."""
    return _binascii.hexlify(token_bytes(nbytes)).decode("ascii")


def token_urlsafe(nbytes: int = DEFAULT_ENTROPY) -> str:
    """Return a random URL-safe string."""
    tok = token_bytes(nbytes)
    return _base64.urlsafe_b64encode(tok).rstrip(b"=").decode("ascii")
