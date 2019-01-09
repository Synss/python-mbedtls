"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport mbedtls._md as _md
from libc.stdlib cimport malloc, free
import binascii
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

    See Also:
        mbedtls.tls.__get_supported_ciphersuites()

    """
    md_lookup = {n: v for n, v in enumerate(MD_NAME)}
    cdef const int* md_types = _md.mbedtls_md_list()
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


cdef class MDBase:
    """Wrap and encapsulate the md library from mbed TLS.

    Parameters:
        name (str): The MD name known to mbed TLS.

    Attributes:
        digest_size (int): The size of the message digest, in bytes.
        block_size (int): The internal block size of the hash
            algorithm in bytes.
        name (str): The name of the message digest.

    """
    def __init__(self, name, buffer, hmac):
        if not isinstance(name, (str, unicode)):
            raise TypeError("name must be a string")
        self._info = _md.mbedtls_md_info_from_string(
            name.upper().encode("ascii"))
        check_error(_md.mbedtls_md_setup(&self._ctx, self._info, hmac))

    def __cinit__(self):
        """Initialize an `md_context` (as NONE)."""
        _md.mbedtls_md_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the internal structures of ctx."""
        _md.mbedtls_md_free(&self._ctx)

    def __str__(self):
        """Return the name of the message digest output."""
        return self.name

    @property
    def _type(self):
        """The type of the message digest output."""
        return _md.mbedtls_md_get_type(self._info)

    @property
    def digest_size(self):
        """The size of the resulting hash in bytes."""
        return _md.mbedtls_md_get_size(self._info)

    @property
    def block_size(self):
        """The internal block size of the hash algorithm in bytes."""
        return self._ctx.md_info.block_size

    @property
    def name(self):
        """The canonical name of the hashing algorithm."""
        return _md.mbedtls_md_get_name(self._info).decode("ascii").lower()

    cdef _finish(self, const unsigned char *output):
        return -0x5100  # Bad input data error.

    def update(self, const unsigned char[:] buffer):
        return -0x5100  # Bad input data error.

    cpdef digest(self):
        """Return the digest output of `message`."""
        cdef size_t sz = self.digest_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(self._finish(output))
            return bytes(output[:self.digest_size])
        finally:
            free(output)

    def hexdigest(self):
        """Like digest except the digest is returned as a string object
        of double length.

        """
        return binascii.hexlify(self.digest()).decode("ascii")
