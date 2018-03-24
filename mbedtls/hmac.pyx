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


cdef class Hmac(_md.MDBase):

    """Wrap and encapsulate HMAC calculations.

    This class is a wrapper for the HMAC calculations in the md module
    of mbed TLS.  The interface follows the recommendation from PEP 452
    for keyed hashes.

    Parameters:
        key (bytes): The key to use.
        name (bytes): The MD name known to mbed TLS.

    Warning:
        The message is cleared after calculation of the digest.  Only
        call :meth:`digest` or :meth:`hexdigest` once per message.

    Attributes:
        digest_size (int): The size of the message digest, in bytes.
        block_size (int): The internal block size of the hash
            algorithm in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(
            self, const unsigned char[:] key not None, name, buffer=None):
        super().__init__(name, buffer, 1)
        check_error(_md.mbedtls_md_hmac_starts(&self._ctx, &key[0], key.size))
        self.update(buffer)

    def update(self, const unsigned char[:] buffer):
        """Update the HMAC object with `buffer`."""
        if buffer is None:
            return
        check_error(
            _md.mbedtls_md_hmac_update(&self._ctx, &buffer[0], buffer.size))

    cdef _finish(self, unsigned char *output):
        """Return the HMAC of key and message."""
        ret = _md.mbedtls_md_hmac_finish(&self._ctx, output)
        if ret != 0:
            return ret
        return _md.mbedtls_md_hmac_reset(&self._ctx)

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
