"""Public key (PK) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free
cimport _pk
cimport mbedtls.random as _random
from functools import partial
import mbedtls.random as _random
from mbedtls.exceptions import check_error, PkError
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


# The following calculations come from mbedtls/library/pkwrite.c.
RSA_PUB_DER_MAX_BYTES = 38 + 2 * _pk.MBEDTLS_MPI_MAX_SIZE
MPI_MAX_SIZE_2 = MBEDTLS_MPI_MAX_SIZE / 2 + MBEDTLS_MPI_MAX_SIZE % 2
RSA_PRV_DER_MAX_BYTES = 47 + 3 * _pk.MBEDTLS_MPI_MAX_SIZE + 5 * MPI_MAX_SIZE_2

ECP_PUB_DER_MAX_BYTES = 30 + 2 * _pk.MBEDTLS_ECP_MAX_BYTES
ECP_PRV_DER_MAX_BYTES = 29 + 3 * _pk.MBEDTLS_ECP_MAX_BYTES

cdef int PUB_DER_MAX_BYTES = max(RSA_PUB_DER_MAX_BYTES, ECP_PUB_DER_MAX_BYTES)
cdef int PRV_DER_MAX_BYTES = max(RSA_PRV_DER_MAX_BYTES, ECP_PRV_DER_MAX_BYTES)

del RSA_PUB_DER_MAX_BYTES, MPI_MAX_SIZE_2, RSA_PRV_DER_MAX_BYTES
del ECP_PUB_DER_MAX_BYTES, ECP_PRV_DER_MAX_BYTES



def _type_from_name(name):
    return {name: n for n, name in enumerate(CIPHER_NAME)}.get(name, 0)


cpdef get_supported_ciphers():
    return CIPHER_NAME


cdef _random.Random __rng = _random.Random()


cpdef _random.Random get_rng():
    return __rng


def _get_md_alg(digestmod):
    """Return the hash object.

    Arguments:
        digestmod: The digest name or digest constructor for the
            Cipher object to use.  It supports any name suitable to
            `mbedtls.hash.new()`.

    """
    # `digestmod` handling below is adapted from CPython's
    # `hmac.py`.
    if callable(digestmod):
        return digestmod
    elif isinstance(digestmod, (str, unicode)):
        return partial(_hash.new, digestmod)
    else:
        raise TypeError("a valid digestmod is required, got %r" % digestmod)


cdef class CipherBase:

    """Wrap and encapsulate the pk library from mbed TLS.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.

    """
    def __init__(self, name):
        check_error(_pk.mbedtls_pk_setup(
            &self._ctx,
            _pk.mbedtls_pk_info_from_type(
                _type_from_name(name)
            )
        ))

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_pk_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_pk_free(&self._ctx)

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

    cpdef bint has_private(self):
        """Return `True` if the key contains a valid private half."""
        raise NotImplementedError

    cpdef bint has_public(self):
        """Return `True` if the key contains a valid public half."""
        raise NotImplementedError

    cpdef verify(self, message, signature, digestmod=None):
        """Verify signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            signature (bytes): The signature to verify.
            digestmod (optional): The digest name or digest constructor.

        Returns:
            bool: True if the verification passed, False otherwise.

        """
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(message)
        cdef unsigned char[:] c_hash = bytearray(md_alg.digest())
        cdef unsigned char[:] c_sig = bytearray(signature)
        ret = _pk.mbedtls_pk_verify(
            &self._ctx, md_alg._type,
            &c_hash[0], c_hash.shape[0],
            &c_sig[0], c_sig.shape[0])
        return ret == 0

    cpdef sign(self, message, digestmod=None):
        """Make signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            digestmod (optional): The digest name or digest constructor.

        Returns:
            bytes or None: The signature or None if the cipher does not
                contain a private key.

        """
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(message)
        cdef unsigned char[:] c_hash = bytearray(md_alg.digest())
        cdef size_t osize = self.key_size
        cdef size_t sig_len = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _pk.mbedtls_pk_sign(
                &self._ctx, md_alg._type,
                &c_hash[0], c_hash.shape[0],
                &output[0], &sig_len,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx)
            if sig_len == 0:
                return None
            else:
                return bytes(bytearray(output[:sig_len]))
        finally:
            free(output)

    cpdef encrypt(self, message):
        """Encrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to encrypt.

        """
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
            return bytes(bytearray(output[:olen]))
        finally:
            free(output)

    cpdef decrypt(self, message):
        """Decrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to decrypt.

        """
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
            return bytes(bytearray(output[:olen]))
        finally:
            free(output)

    cpdef generate(self):
        """Generate a keypair."""
        raise NotImplementedError

    cdef bytes _write(self, int (*fun)(_pk.mbedtls_pk_context *,
                                       unsigned char *, size_t),
                      size_t olen):
        cdef unsigned char[:] buf = bytearray(olen * b"\0")
        cdef int ret = fun(&self._ctx, &buf[0], buf.shape[0])
        check_error(ret)
        # DER format: `ret` is the size of the buffer, offset from the end.
        # PEM format: `ret` is zero.
        if not ret:
            ret = olen
        # Convert _memoryviewslice to bytes.
        # return b"".join(chr(_) for _ in buf[olen - ret:olen])
        return bytes(bytearray(buf[olen - ret:olen]))

    cpdef bytes _write_private_key_der(self):
        return self._write(&_pk.mbedtls_pk_write_key_der,
                           PRV_DER_MAX_BYTES)

    cpdef bytes _write_public_key_der(self):
        return self._write(&_pk.mbedtls_pk_write_pubkey_der,
                           PUB_DER_MAX_BYTES)

    cpdef bytes _write_private_key_pem(self):
        return self._write(&_pk.mbedtls_pk_write_key_pem,
                           PRV_DER_MAX_BYTES * 4 // 3 + 100)

    cpdef bytes _write_public_key_pem(self):
        return self._write(&_pk.mbedtls_pk_write_pubkey_pem,
                           PUB_DER_MAX_BYTES * 4 // 3 + 100)

    cpdef _parse_private_key(self, key, password=None):
        cdef unsigned char[:] c_key = bytearray(key + b"\0")
        cdef unsigned char[:] c_pwd = bytearray(password if password else b"")
        mbedtls_pk_free(&self._ctx)  # The context must be reset on entry.
        check_error(_pk.mbedtls_pk_parse_key(
            &self._ctx, &c_key[0], c_key.shape[0],
            &c_pwd[0] if c_pwd.shape[0] else NULL, c_pwd.shape[0]))

    cpdef _parse_public_key(self, key):
        cdef unsigned char[:] c_key = bytearray(key + b"\0")
        mbedtls_pk_free(&self._ctx)  # The context must be reset on entry.
        check_error(_pk.mbedtls_pk_parse_public_key(
            &self._ctx, &c_key[0], c_key.shape[0]))

    def import_(self, key, password=None):
        """Import a key (public or private half).

        The public half is automatically generated upon importing a
        private key.

        Arguments:
            key (bytes): The key in PEM or DER format.
            password (bytes, optional): The password for
                password-protected private keys.

        """
        try:
            self._parse_private_key(key, password)
        except PkError:
            self._parse_public_key(key)

    def export(self, format="PEM"):
        """Export the keys.

        Arguments:
            format (string): One of {"PEM", "DER"}, defaults to PEM.

        Returns:
            tuple(bytes, bytes): The private key and the public key.

        """
        prv = b""
        if self.has_private():
            if format == "DER":
                prv = self._write_private_key_der()
            else:
                prv = self._write_private_key_pem()
        pub = b""
        if self.has_public():
            if format == "DER":
                pub = self._write_public_key_der()
            else:
                pub = self._write_public_key_pem()
        return prv, pub


cpdef check_pair(CipherBase pub, CipherBase pri):
    """Check if a public-private pair of keys matches."""
    return _pk.mbedtls_pk_check_pair(&pub._ctx, &pri._ctx) == 0
