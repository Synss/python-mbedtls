"""Public key (PK) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


from libc.stdlib cimport malloc, free
cimport _pk
cimport mbedtls.random as _random
import mbedtls.random as _random
from mbedtls.exceptions import check_error, RsaError
import mbedtls.hash as _hash


__all__ = ("CipherBase", "CIPHER_NAME", "check_pair",
           "get_supported_ciphers", "get_rng")


CIPHER_NAME = (
    b"NONE",
    b"RSA",
    b"EC",     # ECKEY
    b"EC_DH",  # ECKEY_DH
    b"ECDSA",
    # b"RSA_ALT",
    # b"RSASSA_PSS",
)


def _type_from_name(name):
    return {name: n for n, name in enumerate(CIPHER_NAME)}.get(name, 0)


cpdef get_supported_ciphers():
    return CIPHER_NAME


cdef _random.Random __rng = _random.Random()


cpdef _random.Random get_rng():
    return __rng


cdef class CipherBase:

    """Wrap and encapsulate the pk library from mbed TLS.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.
        digestmod: The digest name or digest constructor for the
            Cipher object to use.  It supports any name suitable to
            `mbedtls.hash.new()`.

    """
    def __init__(self, name, *, digestmod):
        check_error(_pk.mbedtls_pk_setup(
            &self._ctx,
            _pk.mbedtls_pk_info_from_type(
                _type_from_name(name)
            )
        ))

        # `digestmod` handling below is adapted from CPython's
        # `hmac.py`.
        if callable(digestmod):
            self._md_alg = digestmod()._type
        elif isinstance(digestmod, str):
            self._md_alg = _hash.new(digestmod)._type
        else:
            raise ValueError("a valid digestmod is required")

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_pk_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_pk_free(&self._ctx)

    property _md_type:
        """Return the type of the digestmod."""
        def __get__(self):
            return self._md_alg

    property _type:
        """Return the type of the cipher."""
        def __get__(self):
            return _pk.mbedtls_pk_get_type(&self._ctx)
    
    property name:
        """Return the name of the cipher."""
        def __get__(self):
            return _pk.mbedtls_pk_get_name(&self._ctx)

    property _bitlen:
        """Return the size of the key, in bits."""
        def __get__(self):
            return _pk.mbedtls_pk_get_bitlen(&self._ctx)

    property key_size:
        """Return the size of the key, in bytes."""
        def __get__(self):
            return _pk.mbedtls_pk_get_len(&self._ctx)

    # cpdef verify(self, hash_name, hash, sig):
    #     cdef _pk.mbedtls_md_type_t md_alg = 0  # TODO
    #     cdef unsigned char[:] c_hash = bytearray(hash)
    #     cdef unsigned char[:] c_sig = bytearray(sig)
    #     return _pk.mbedtls_pk_verify(
    #         &self._ctx, md_alg,
    #         &c_hash[0], c_hash.shape[0],
    #         &c_sig[0], c_sig.shape[0])

    cpdef sign(self):
        pass

    cpdef encrypt(self, message):
        cdef unsigned char[:] buf = bytearray(message)
        cdef size_t osize = self.key_size
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_encrypt(
                &self._ctx, &buf[0], buf.shape[0],
                output, &olen, osize,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes([output[n] for n in range(olen)])
        finally:
            free(output)

    cpdef decrypt(self, message):
        cdef unsigned char[:] buf = bytearray(message)
        cdef size_t osize = self.key_size
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_decrypt(
                &self._ctx, &buf[0], buf.shape[0],
                output, &olen, osize,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes([output[n] for n in range(olen)])
        finally:
            free(output)

    cpdef generate(self):
        """Generate a keypair."""
        raise NotImplementedError

    cdef bytes _write(self, int (*fun)(_pk.mbedtls_pk_context *,
                                       unsigned char *, size_t)):
        cdef unsigned char[:] buf = bytearray(1024 * b"\0")
        cdef int ret = fun(&self._ctx, &buf[0], buf.shape[0])
        if ret > 0:
            # DER format: `ret` is the size of the buffer, offset from the end.
            key = bytes([buf[n] for n
                         in range(buf.shape[0] - ret, buf.shape[0])])
            if len(key) != ret:
                raise RsaError(-1, "the generated key length is wrong")
        elif ret == 0:
            # PEM format: `ret` is zero.
            key = bytes(buf[n] for n
                        in range(buf.shape[0])).split(b"\0", 1)[0]
        else:  # ret < 0
            # The return value is an error.
            check_error(ret)
        return key

    cpdef bytes _write_private_key_der(self):
        return self._write(&_pk.mbedtls_pk_write_key_der)

    cpdef bytes _write_public_key_der(self):
        return self._write(&_pk.mbedtls_pk_write_pubkey_der)

    cpdef bytes _write_private_key_pem(self):
        return self._write(&_pk.mbedtls_pk_write_key_pem)

    cpdef bytes _write_public_key_pem(self):
        return self._write(&_pk.mbedtls_pk_write_pubkey_pem)

    cpdef _parse_private_key(self, key, password=None):
        cdef unsigned char[:] c_key = bytearray(key + b"\0")
        cdef unsigned char[:] c_pwd = bytearray(password if password else b"")
        check_error(_pk.mbedtls_pk_parse_key(
            &self._ctx,
            &c_key[0], c_key.shape[0],
            &c_pwd[0] if c_pwd.shape[0] else NULL, c_pwd.shape[0]))

    cpdef _parse_public_key(self, key):
        cdef unsigned char[:] c_key = bytearray(key + b"\0")
        check_error(_pk.mbedtls_pk_parse_public_key(
            &self._ctx, &c_key[0], c_key.shape[0]))


cpdef check_pair(CipherBase pub, CipherBase pri):
    """Check if a public-private pair of keys matches."""
    return _pk.mbedtls_pk_check_pair(&pub._ctx, &pri._ctx) == 0
