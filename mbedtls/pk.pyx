"""Public key (PK) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls.pk as _pk
cimport mbedtls.random as _random

from functools import partial

import mbedtls.random as _random
from mbedtls.exceptions import check_error, PkError
import mbedtls.hash as _hash


__all__ = ("CIPHER_NAME", "check_pair", "get_supported_ciphers", "RSA")


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


cpdef check_pair(CipherBase pub, CipherBase pri):
    """Check if a public-private pair of keys matches."""
    return _pk.mbedtls_pk_check_pair(&pub._ctx, &pri._ctx) == 0


def _type_from_name(name):
    return {name: n for n, name in enumerate(CIPHER_NAME)}.get(name, 0)


cpdef get_supported_ciphers():
    return CIPHER_NAME


cdef _random.Random __rng = _random.Random()


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

    def verify(self,
               const unsigned char[:] message not None,
               const unsigned char[:] signature not None,
               digestmod=None):
        """Verify signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            signature (bytes): The signature to verify.
            digestmod (optional): The digest name or digest constructor.

        Return:
            bool: True if the verification passed, False otherwise.

        """
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(message)
        cdef const unsigned char[:] hash_ = md_alg.digest()
        return _pk.mbedtls_pk_verify(
            &self._ctx, md_alg._type,
            &hash_[0], hash_.size,
            &signature[0], signature.size) == 0

    def sign(self,
             const unsigned char[:] message not None,
             digestmod=None):
        """Make signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            digestmod (optional): The digest name or digest constructor.

        Return:
            bytes or None: The signature or None if the cipher does not
                contain a private key.

        """
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(message)
        cdef const unsigned char[:] hash_ = md_alg.digest()
        cdef size_t sig_len = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            self.key_size * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _pk.mbedtls_pk_sign(
                &self._ctx, md_alg._type,
                &hash_[0], hash_.size,
                &output[0], &sig_len,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx)
            if sig_len == 0:
                return None
            else:
                return bytes(output[:sig_len])
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        """Encrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to encrypt.

        """
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            self.key_size * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_encrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes(output[:olen])
        finally:
            free(output)

    def decrypt(self, const unsigned char[:] message not None):
        """Decrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to decrypt.

        """
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            self.key_size * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_decrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes(output[:olen])
        finally:
            free(output)

    def generate(self):
        """Generate a keypair."""
        raise NotImplementedError

    cdef bytes _write(self, int (*fun)(_pk.mbedtls_pk_context *,
                                       unsigned char *, size_t),
                      size_t olen):
        cdef unsigned char[:] buf = bytearray(olen * b"\0")
        cdef int ret = fun(&self._ctx, &buf[0], buf.size)
        check_error(ret)
        # DER format: `ret` is the size of the buffer, offset from the end.
        # PEM format: `ret` is zero.
        if not ret:
            ret = olen
        # cast unsigned char[:] -> bytearray -> bytes
        return bytes(bytearray(buf[olen - ret:olen]))

    def from_buffer(self, key, password=None):
        """Import a key (public or private half).

        The public half is automatically generated upon importing a
        private key.

        Arguments:
            key (bytes): The key in PEM or DER format.
            password (bytes, optional): The password for
                password-protected private keys.

        """
        if password is None:
            password = bytearray()
        cdef unsigned char[:] pwd_ = bytearray(password)
        cdef unsigned char[:] key_ = bytearray(key + b"\0")
        mbedtls_pk_free(&self._ctx)  # The context must be reset on entry.
        try:
            check_error(_pk.mbedtls_pk_parse_key(
                &self._ctx, &key_[0], key_.size,
                &pwd_[0] if pwd_.size else NULL, pwd_.size))
        except PkError:
            check_error(_pk.mbedtls_pk_parse_public_key(
                &self._ctx, &key_[0], key_.size))

    from_DER = from_buffer

    def from_PEM(self, key, password=None):
        """Import a key (public and private half)."""
        self.from_buffer(key.encode("ascii"), password=password)

    def to_PEM(self):
        """Return the RSA in PEM format.

        Return:
            tuple(str, str): The private key and the public key.

        """
        prv, pub = "", ""
        if self.has_private():
            prv = self._write(&_pk.mbedtls_pk_write_key_pem,
                              PRV_DER_MAX_BYTES * 4 // 3 + 100).decode("ascii")
        if self.has_public():
            pub = self._write(&_pk.mbedtls_pk_write_pubkey_pem,
                              PUB_DER_MAX_BYTES * 4 // 3 + 100).decode("ascii")
        return prv, pub

    def __str__(self):
        return "\n".join(self.to_PEM())

    def to_DER(self):
        """Return the RSA in DER format.

        Return:
            tuple(bytes, bytes): The private key and the public key.

        """
        prv, pub = b"", b""
        if self.has_private():
            prv = self._write(&_pk.mbedtls_pk_write_key_der,
                              PRV_DER_MAX_BYTES)
        if self.has_public():
            pub = self._write(&_pk.mbedtls_pk_write_pubkey_der,
                              PUB_DER_MAX_BYTES)
        return prv, pub

    to_bytes = to_DER

    def __bytes__(self):
        return b"\n".join(self.to_DER())


cdef class RSA(CipherBase):

    """RSA public-key cryptosystem."""

    def __init__(self):
        super().__init__(b"RSA")

    cpdef bint has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _pk.mbedtls_rsa_check_privkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    cpdef bint has_public(self):
        """Return `True` if the key contains a valid public half."""
        return _pk.mbedtls_rsa_check_pubkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    def generate(self, unsigned int key_size=2048, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        """
        check_error(_pk.mbedtls_rsa_gen_key(
            _pk.mbedtls_pk_rsa(self._ctx), &_random.mbedtls_ctr_drbg_random,
            &__rng._ctx, key_size, exponent))
