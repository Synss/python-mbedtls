"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


from libc.stdlib cimport malloc, free
cimport _md
import _md
from mbedtls.exceptions import *


algorithms_guaranteed = _md.algorithms_guaranteed
algorithms_available = _md.algorithms_available


cdef class Hmac(_md.MDBase):

    """Wrap and encapsulate HMAC calculations.

    This class is a wrapper for the HMAC calculations in the md module
    of mbed TLS.  The interface follows the recommendation from PEP 452
    for keyed hashes.

    Parameters:
        key (bytes): The key to use.
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        digest_size (int): The size of the message digest, in bytes.
        block_size (int): Not implemented.
        name (bytes): The name of the message digest.

    """
    def __init__(self, key, name, buffer=None):
        super().__init__(name, buffer, 1)
        cdef unsigned char[:] c_key = bytearray(key)
        check_error(_md.mbedtls_md_hmac_starts(
            &self._ctx, &c_key[0], c_key.shape[0]))
        self.update(buffer)

    cdef _update(self, const unsigned char *input, size_t ilen):
        """Update the HMAC object with `buffer`."""
        return _md.mbedtls_md_hmac_update(&self._ctx, input, ilen)

    cdef _finish(self, unsigned char *output):
        """Return the HMAC of key and message."""
        return _md.mbedtls_md_hmac_finish(&self._ctx, output)

    cpdef copy(self):
        """Return a copy ("clone") of the HMAC object.

        Warning:
            Not implemented in mbed TLS, raises NotImplementedError.

        """
        raise NotImplementedError


def new(key, buffer=None, digestmod=None):
    """A generic constructor that takes the key algorithm as its first
    parameter.

    """
    if digestmod is None:
        digestmod = "md5"
    return Hmac(key, digestmod, buffer)


def md2(key, buffer=None):
    """MD2 message-digest algorithm."""
    return Hash(key, buffer, digestmod="md2")


def md4(key, buffer=None):
    """MD4 message-digest algorithm."""
    return Hash(key, buffer, digestmod="md4")


def md5(key, buffer=None):
    """MD5 message-digest algorithm."""
    return Hash(key, buffer, digestmod="md5")


def sha1(key, buffer=None):
    """Secure Hash Algorithm 1 (SHA-1)."""
    return Hash(key, buffer, digestmod="sha1")


def sha224(key, buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 224 bits hash value."""
    return Hash(key, buffer, digestmod="sha224")


def sha256(key, buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 256 bits hash value."""
    return Hash(key, buffer, digestmod="sha256")


def sha384(key, buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 384 bits hash value."""
    return Hash(key, buffer, digestmod="sha384")


def sha512(key, buffer=None):
    """Secure Hash Algorithm 2 (SHA-2) with 512 bits hash value."""
    return Hash(key, buffer, digestmod="sha512")


def ripemd160(key, buffer=None):
    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value."""
    return Hash(key, buffer, digestmod="ripemd160")
