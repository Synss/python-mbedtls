# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Generic message digest wrapper (hash algorithm)."""


import mbedtls._md as _md

algorithms_guaranteed = _md.algorithms_guaranteed
algorithms_available = _md.algorithms_available


Hmac = _md.Hmac


def new(key, buffer=None, digestmod=None):
    """A generic constructor that takes the key algorithm as its first
    parameter.

    """
    if digestmod is None:
        digestmod = "md5"
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
    }.get(digestmod.lower(), 64)
    return Hmac(key, digestmod, buffer, block_size=block_size)


def md2(key, buffer=None):
    """MD2 message-digest algorithm."""
    return new(key, buffer, "md2")


def md4(key, buffer=None):
    """MD4 message-digest algorithm."""
    return new(key, buffer, "md4")


def md5(key, buffer=None):
    """MD5 message-digest algorithm."""
    return new(key, buffer, "md5")


def sha1(key, buffer=None):
    """Secure Hmac Algorithm 1 (SHA-1)."""
    return new(key, buffer, "sha1")


def sha224(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 224 bits hash value."""
    return new(key, buffer, "sha224")


def sha256(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 256 bits hash value."""
    return new(key, buffer, "sha256")


def sha384(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 384 bits hash value."""
    return new(key, buffer, "sha384")


def sha512(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 512 bits hash value."""
    return new(key, buffer, "sha512")


def ripemd160(key, buffer=None):
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return new(key, buffer, "ripemd160")
