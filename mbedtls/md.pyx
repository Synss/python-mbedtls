"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport cmd
from libc.stdlib cimport malloc, free
from mbedtls.exceptions import *


MD_NAME = (
    # Define as bytes to map to `const char*` without conversion.
    b"NONE",
    b"MD2",
    b"MD4",
    b"MD5",
    b"SHA1",
    b"SHA224",
    b"SHA256",
    b"SHA384",
    b"SHA512",
    b"RIPEMD160",
)


def __get_supported_mds():
    """Return the set of digests supported by the generic
    message digest module.

    """
    md_lookup = {n: v for n, v in enumerate(MD_NAME)}
    cdef const int* md_types = cmd.mbedtls_md_list()
    cdef size_t n = 0
    mds = set()
    while md_types[n]:
        mds.add(md_lookup[md_types[n]])
        n += 1
    return mds


algorithms_guaranteed = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
algorithms_available = {name.decode("ascii").lower()
                        for name in  __get_supported_mds()}


__all__ = algorithms_guaranteed + ("new", "algorithms_guaranteed",
                                   "algorithms_available")


cdef _c_get_size(const cmd.mbedtls_md_info_t* md_info):
    """Return the size of the message digest output."""
    return cmd.mbedtls_md_get_size(md_info)


cdef _c_get_name(const cmd.mbedtls_md_info_t* md_info):
    """Return the name of the message digest output."""
    return cmd.mbedtls_md_get_name(md_info)


cdef class MDBase:
    """Wrap and encapsulate the md library from mbed TLS.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    cdef const cmd.mbedtls_md_info_t* _info
    cdef cmd.mbedtls_md_context_t _ctx

    def __init__(self, name, buffer, hmac):
        if not isinstance(name, str):
            raise TypeError("name must be a string")
        self._info = cmd.mbedtls_md_info_from_string(
            name.upper().encode("ascii"))
        check_error(cmd.mbedtls_md_setup(&self._ctx, self._info, hmac))

    def __cinit__(self):
        """Initialize an `md_context` (as NONE)."""
        cmd.mbedtls_md_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the internal structures of ctx."""
        cmd.mbedtls_md_free(&self._ctx)

    def __str__(self):
        """Return the name of the message digest output."""
        return self.name

    @property
    def digest_size(self):
        """The size of the resulting hash in bytes."""
        return _c_get_size(self._info)

    @property
    def block_size(self):
        """The internal block size of the hash algorithm in bytes."""
        raise NotImplementedError

    @property
    def name(self):
        """The canonical name of the hashing algorithm."""
        return _c_get_name(self._info).decode("ascii").lower()


cdef class Hash(MDBase):

    """Wrap and encapsulate the md library from mbed TLS.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self, name, buffer=None):
        super().__init__(name, buffer, 0)
        check_error(cmd.mbedtls_md_starts(&self._ctx))
        self.update(buffer)

    cpdef update(self, buffer):
        """Update the hash object with the `buffer`."""
        if not buffer:
            return
        cdef unsigned char[:] buf = bytearray(buffer)
        check_error(cmd.mbedtls_md_update(&self._ctx, &buf[0], buf.shape[0]))

    cpdef digest(self):
        """Return the digest output of `message`."""
        cdef size_t sz = self.digest_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(cmd.mbedtls_md_finish(&self._ctx, output))
            return bytes([output[n] for n in range(self.digest_size)])
        finally:
            free(output)


cdef class Hmac(MDBase):

    def __init__(self, key, name, buffer=None):
        super().__init__(name, buffer, 1)
        cdef unsigned char[:] c_key = bytearray(key)
        check_error(cmd.mbedtls_md_hmac_starts(
            &self._ctx, &c_key[0], c_key.shape[0]))
        self.update(buffer)

    cpdef update(self, buffer):
        """Update the HMAC object with `buffer`."""
        if not buffer:
            return
        cdef unsigned char[:] buf = bytearray(buffer)
        check_error(cmd.mbedtls_md_hmac_update(&self._ctx, &buf[0],
                                               buf.shape[0]))

    cpdef digest(self):
        """Return the HMAC of key and message."""
        cdef size_t sz = self.digest_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(cmd.mbedtls_md_hmac_finish(&self._ctx, output))
            return bytes([output[n] for n in range(self.digest_size)])
        finally:
            free(output)


def new_hmac(key, buffer=None, digestmod=None):
    return Hmac(key, digestmod, buffer)


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
