# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Generic message digest wrapper (hash algorithm)."""


import mbedtls._md as _md

algorithms_guaranteed = _md.algorithms_guaranteed
algorithms_available = _md.algorithms_available


Hash = _md.Hash


def new(name, buffer=None):
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


def md2(buffer=None):
    """MD2 message-digest algorithm."""
    return new("md2", buffer)


def md4(buffer=None):
    """MD4 message-digest algorithm."""
    return new("md4", buffer)


def md5(buffer=None):
    """MD5 message-digest algorithm."""
    return new("md5", buffer)


def sha1(buffer=None):
    """Secure Hash Algorithm 1 (SHA-1)."""
    return new("sha1", buffer)


def sha224(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 224 bits hash value."""
    return new("sha224", buffer)


def sha256(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 256 bits hash value."""
    return new("sha256", buffer)


def sha384(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 384 bits hash value."""
    return new("sha384", buffer)


def sha512(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 512 bits hash value."""
    return new("sha512", buffer)


def ripemd160(buffer=None):
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return new("ripemd160", buffer)
