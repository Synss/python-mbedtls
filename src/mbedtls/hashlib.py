# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Generic message digest wrapper (hash algorithm)."""


import sys
from typing import Optional

from mbedtls._md import Hash as Hash
from mbedtls._md import algorithms_available as algorithms_available
from mbedtls._md import algorithms_guaranteed as algorithms_guaranteed

if sys.version_info < (3, 8):
    from typing_extensions import Protocol
else:
    from typing import Protocol


# Work around pyflakes' F401: imported but unused
assert algorithms_available
assert algorithms_guaranteed


class Algorithm(Protocol):
    def __call__(self, buffer: Optional[bytes] = ...) -> Hash:
        ...


def new(name: str, buffer: Optional[bytes] = None) -> Hash:
    """A generic constructor that takes the string name of the desired
    algorithm as its first parameter.

    """
    block_size = {
        "md2": 16,
        "md4": 64,
        "md5": 64,
        "sha1": 64,
        "sha224": 64,
        "sha256": 64,
        "sha384": 128,
        "sha512": 128,
        "ripemd160": 64,
    }.get(name.lower(), 64)
    return Hash(name, buffer, block_size=block_size)


def md2(buffer: Optional[bytes] = None) -> Hash:
    """MD2 message-digest algorithm."""
    return new("md2", buffer)


def md4(buffer: Optional[bytes] = None) -> Hash:
    """MD4 message-digest algorithm."""
    return new("md4", buffer)


def md5(buffer: Optional[bytes] = None) -> Hash:
    """MD5 message-digest algorithm."""
    return new("md5", buffer)


def sha1(buffer: Optional[bytes] = None) -> Hash:
    """Secure Hash Algorithm 1 (SHA-1)."""
    return new("sha1", buffer)


def sha224(buffer: Optional[bytes] = None) -> Hash:
    """Secure Hash Algorithm 2 (SHA-2) with 224 bits hash value."""
    return new("sha224", buffer)


def sha256(buffer: Optional[bytes] = None) -> Hash:
    """Secure Hash Algorithm 2 (SHA-2) with 256 bits hash value."""
    return new("sha256", buffer)


def sha384(buffer: Optional[bytes] = None) -> Hash:
    """Secure Hash Algorithm 2 (SHA-2) with 384 bits hash value."""
    return new("sha384", buffer)


def sha512(buffer: Optional[bytes] = None) -> Hash:
    """Secure Hash Algorithm 2 (SHA-2) with 512 bits hash value."""
    return new("sha512", buffer)


def ripemd160(buffer: Optional[bytes] = None) -> Hash:
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return new("ripemd160", buffer)
