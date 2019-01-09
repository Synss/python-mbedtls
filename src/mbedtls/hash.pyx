"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free
cimport mbedtls._md as _md
import mbedtls._md as _md
from mbedtls.exceptions import *


algorithms_guaranteed = _md.algorithms_guaranteed
algorithms_available = _md.algorithms_available


cdef class Hash(_md.MDBase):

    """Wrap and encapsulate hash calculations.

    This class is a wrapper for the hash calculations in the md module
    of mbed TLS.  The interface follows the recommendation from PEP 452
    for unkeyed hashes.

    Parameters:
        name (str): The MD name known to mbed TLS.

    Attributes:
        digest_size (int): The size of the message digest, in bytes.
        block_size (int): The internal block size of the hash
            algorithm in bytes.
        name (str): The name of the message digest.

    """
    def __init__(self, name, buffer=None):
        super().__init__(name, buffer, 0)
        check_error(_md.mbedtls_md_starts(&self._ctx))
        self.update(buffer)

    def update(self, const unsigned char[:] buffer):
        """Update the hash object with the `buffer`."""
        if buffer is None:
            return
        check_error(
            _md.mbedtls_md_update(&self._ctx, &buffer[0], buffer.size))

    cdef _finish(self, unsigned char *output):
        """Return the digest output of `message`."""
        return _md.mbedtls_md_finish(&self._ctx, output)

    cpdef copy(self):
        """Return a copy ("clone") of the hash object."""
        obj = Hash(self.name)
        check_error(_md.mbedtls_md_clone(&obj._ctx, &self._ctx))
        return obj


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
