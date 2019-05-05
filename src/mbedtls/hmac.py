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


Hmac = _md.Hmac


def new(key, buffer=None, digestmod=None):
    """A generic constructor that takes the key algorithm as its first
    parameter.

    """
    if digestmod is None:
        digestmod = "md5"
    return Hmac(key, digestmod, buffer)


def md2(key, buffer=None):
    """MD2 message-digest algorithm."""
    return Hmac(key, "md2", buffer)


def md4(key, buffer=None):
    """MD4 message-digest algorithm."""
    return Hmac(key, "md4", buffer)


def md5(key, buffer=None):
    """MD5 message-digest algorithm."""
    return Hmac(key, "md5", buffer)


def sha1(key, buffer=None):
    """Secure Hmac Algorithm 1 (SHA-1)."""
    return Hmac(key, "sha1", buffer)


def sha224(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 224 bits hash value."""
    return Hmac(key, "sha224", buffer)


def sha256(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 256 bits hash value."""
    return Hmac(key, "sha256", buffer)


def sha384(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 384 bits hash value."""
    return Hmac(key, "sha384", buffer)


def sha512(key, buffer=None):
    """Secure Hmac Algorithm 2 (SHA-2) with 512 bits hash value."""
    return Hmac(key, "sha512", buffer)


def ripemd160(key, buffer=None):
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return Hmac(key, "ripemd160", buffer)
