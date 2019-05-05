"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = (
    "Copyright 2015, Elaborated Networks GmbH, "
    "Copyright 2019, Mathias Laurin"
)
__license__ = "MIT License"


import mbedtls._md as _md
from mbedtls.exceptions import *


algorithms_guaranteed = _md.algorithms_guaranteed
algorithms_available = _md.algorithms_available


Hash = _md.Hash


def new(name, buffer=None):
    """A generic constructor that takes the string name of the desired
    algorithm as its first parameter.

    """
    return Hash(name, buffer)


def md2(buffer=None):
    """MD2 message-digest algorithm."""
    return Hash("md2", buffer)


def md4(buffer=None):
    """MD4 message-digest algorithm."""
    return Hash("md4", buffer)


def md5(buffer=None):
    """MD5 message-digest algorithm."""
    return Hash("md5", buffer)


def sha1(buffer=None):
    """Secure Hash Algorithm 1 (SHA-1)."""
    return Hash("sha1", buffer)


def sha224(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 224 bits hash value."""
    return Hash("sha224", buffer)


def sha256(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 256 bits hash value."""
    return Hash("sha256", buffer)


def sha384(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 384 bits hash value."""
    return Hash("sha384", buffer)


def sha512(buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 512 bits hash value."""
    return Hash("sha512", buffer)


def ripemd160(buffer=None):
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return Hash("ripemd160", buffer)
