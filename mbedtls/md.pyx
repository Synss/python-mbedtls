"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport cmd
from libc.stdlib cimport malloc, free
from mbedtls.exceptions import *

__all__ = ("Sha1", "Sha224", "Sha256", "Sha384", "Sha512",
           "Md5", "Ripemd160")


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


def get_supported_mds():
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


cdef _c_get_size(const cmd.mbedtls_md_info_t* md_info):
    """Return the size of the message digest output."""
    return cmd.mbedtls_md_get_size(md_info)


cdef _c_get_type(const cmd.mbedtls_md_info_t* md_info):
    """Return the type of the message digest output."""
    return cmd.mbedtls_md_get_type(md_info)


cdef _c_get_name(const cmd.mbedtls_md_info_t* md_info):
    """Return the name of the message digest output."""
    return cmd.mbedtls_md_get_name(md_info)


cdef _c_md(const cmd.mbedtls_md_info_t* md_info,
           unsigned char[:] input):
    """Return the digest output of `input`."""
    cdef size_t sz = _c_get_size(md_info)
    cdef unsigned char* output = <unsigned char*>malloc(
        sz * sizeof(unsigned char))
    if not output:
        raise MemoryError()
    cdef int err
    try:
        err = cmd.mbedtls_md(
            md_info, &input[0], input.shape[0],
            output)
        check_error(err)
        # The list comprehension is required.
        return bytes([output[n] for n in range(sz)])
    finally:
        free(output)


cdef _c_md_file(const cmd.mbedtls_md_info_t* md_info,
                char[:] path):
    """Return the digest of the contents of the file at `path`."""
    cdef size_t sz = _c_get_size(md_info)
    cdef unsigned char* output = <unsigned char*>malloc(
        sz * sizeof(unsigned char))
    if not output:
        raise MemoryError()
    cdef int err
    try:
        err = cmd.mbedtls_md_file(md_info, &path[0], output)
        check_error(err)
        # The list comprehension is required.
        return bytes([output[n] for n in range(sz)])
    finally:
        free(output)


cdef _c_md_hmac(const cmd.mbedtls_md_info_t* md_info,
                unsigned char[:] key,
                unsigned char[:] input):
    """Return the HMAC of the input with key."""
    cdef size_t sz = _c_get_size(md_info)
    cdef unsigned char* output = <unsigned char*>malloc(
        sz * sizeof(unsigned char))
    if not output:
        raise MemoryError()
    cdef int err
    try:
        err = cmd.mbedtls_md_hmac(
            md_info, &key[0], key.shape[0], &input[0], input.shape[0], output)
        check_error(err)
        # The list comprehension is required.
        return bytes([output[n] for n in range(sz)])
    finally:
        free(output)


cdef class MessageDigest:

    """Wrap and encapsulate the md library from mbed TLS.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    cdef const cmd.mbedtls_md_info_t* _info

    def __init__(self, name):
        self._info = cmd.mbedtls_md_info_from_string(name)

    def __str__(self):
        """Return the name of the message digest output."""
        return self.name.decode("ascii")

    @property
    def size(self):
        """Return the size of the message digest output."""
        return _c_get_size(self._info)

    @property
    def _type(self):
        """Return the type of the message digest output."""
        return _c_get_type(self._info)

    @property
    def name(self):
        """Return the name of the message digest output."""
        return _c_get_name(self._info)

    cpdef digest(self, message):
        """Return the digest output of `message`."""
        return _c_md(self._info, bytearray(message))

    cpdef digest_file(self, path):
        """Return the digest of the contents of the file at `path`."""
        return _c_md_file(self._info, bytearray(path.encode("ascii")))

    cpdef digest_hmac(self, key, message):
        """Return the HMAC of key and message."""
        return _c_md_hmac(self._info, bytearray(key), bytearray(message))


class Md2(MessageDigest):

    """MD2 message-digest algorithm.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"MD2")


class Md4(MessageDigest):

    """MD4 message-digest algorithm.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"MD4")


class Md5(MessageDigest):

    """MD5 message-digest algorithm.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"MD5")


class Sha1(MessageDigest):

    """Secure Hash Algorithm 1 (SHA-1).

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"SHA1")


class Sha224(MessageDigest):

    """Secure Hash Algorithm 2 (SHA-2) with 224 bits hash value.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"SHA224")


class Sha256(MessageDigest):

    """Secure Hash Algorithm 2 (SHA-2) with 256 bits hash value.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"SHA256")


class Sha384(MessageDigest):

    """Secure Hash Algorithm 2 (SHA-2) with 384 bits hash value.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"SHA384")


class Sha512(MessageDigest):

    """Secure Hash Algorithm 2 (SHA-2) with 512 bits hash value.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"SHA512")


class Ripemd160(MessageDigest):

    """RACE Integrity Primitives Evaluation Message Digest (RIPEMD) with
    160 bits hash value.

    Parameters:
        name (bytes): The MD name known to mbed TLS.

    Attributes:
        size (int): The size of the message digest, in bytes.
        name (bytes): The name of the message digest.

    """
    def __init__(self):
        super().__init__(b"RIPEMD160")
