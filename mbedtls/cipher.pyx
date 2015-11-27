"""Ciphers for symmetric encryption and decryption."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport ccipher
from libc.stdlib cimport malloc, free
import enum


class ErrorBase(Exception):
    """Base class for cipher exceptions."""


class InvalidKeyLengthError(ErrorBase):
    pass


class InvalidInputLengthError(ErrorBase):
    pass


class FeatureUnavailableError(ErrorBase):
    pass


class BadInputDataError(ErrorBase):
    pass


class AllocFailedError(ErrorBase):
    pass


class InvalidPaddingError(ErrorBase):
    pass


class FullBlockExpectedError(ErrorBase):
    pass


class AuthFailedError(ErrorBase):
    pass


class UnsupportedCipherError(ErrorBase):
    """Raised upon trying to instantiate an unsupported cipher."""


CIPHER_NAME = (
    # Define as bytes to map to `const char*` without conversion.
    b"NONE",
    b"NULL",
    b"AES-128-ECB",
    b"AES-192-ECB",
    b"AES-256-ECB",
    b"AES-128-CBC",
    b"AES-192-CBC",
    b"AES-256-CBC",
    b"AES-128-CFB128",
    b"AES-192-CFB128",
    b"AES-256-CFB128",
    b"AES-128-CTR" ,
    b"AES-192-CTR",
    b"AES-256-CTR",
    b"AES-128-GCM",
    b"AES-192-GCM",
    b"AES-256-GCM",
    b"CAMELLIA-128-ECB",
    b"CAMELLIA-192-ECB",
    b"CAMELLIA-256-ECB",
    b"CAMELLIA-128-CBC",
    b"CAMELLIA-192-CBC",
    b"CAMELLIA-256-CBC",
    b"CAMELLIA-128-CFB128",
    b"CAMELLIA-192-CFB128",
    b"CAMELLIA-256-CFB128",
    b"CAMELLIA-128-CTR",
    b"CAMELLIA-192-CTR",
    b"CAMELLIA-256-CTR",
    b"CAMELLIA-128-GCM",
    b"CAMELLIA-192-GCM",
    b"CAMELLIA-256-GCM",
    b"DES-ECB",
    b"DES-CBC",
    b"DES-EDE-ECB",
    b"DES-EDE-CBC",
    b"DES-EDE3-ECB",
    b"DES-EDE3-CBC",
    b"BLOWFISH-ECB",
    b"BLOWFISH-CBC",
    b"BLOWFISH-CFB64",
    b"BLOWFISH-CTR",
    b"ARC4-128",
    b"AES-128-CCM",
    b"AES-192-CCM",
    b"AES-256-CCM",
    b"CAMELLIA-128-CCM",
    b"CAMELLIA-192-CCM",
    b"CAMELLIA-256-CCM",
)


OP_DECRYPT, OP_ENCRYPT = 0, 1


cpdef check_error(const int err):
    if not err:
        return
    else:
        raise {
            # Blowfish-specific
            -0x0016: InvalidKeyLengthError,
            -0x0018: InvalidInputLengthError,
            # Common errors
            -0x6080: FeatureUnavailableError,
            -0x6100: BadInputDataError,
            -0x6180: AllocFailedError,
            -0x6200: InvalidPaddingError,
            -0x6280: FullBlockExpectedError,
            -0x6300: AuthFailedError,
        }.get(err, ErrorBase)()


cpdef get_supported_ciphers():
    """Returns the set of ciphers supported by the generic
    cipher module.

    """
    cipher_lookup = {n: v for n, v in enumerate(CIPHER_NAME)}
    cdef const int* cipher_types = ccipher.mbedtls_cipher_list()
    cdef size_t n = 0
    ciphers = set()
    while cipher_types[n]:
        ciphers.add(cipher_lookup[cipher_types[n]])
        n += 1
    return ciphers


cdef class Cipher:

    def __init__(self, cipher_name):
        self._setup(cipher_name)

    def __repr__(self):
        return ("%s(" % self.__class__.__name__ +
                "%r" % self.name +
                ")")

    cdef ccipher.mbedtls_cipher_context_t _ctx

    def __cinit__(self):
        """Initialize a `cipher_context` (as NONE)."""
        ccipher.mbedtls_cipher_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the cipher-specific context of ctx."""
        ccipher.mbedtls_cipher_free(&self._ctx)

    cdef _c_setup(self, const ccipher.mbedtls_cipher_info_t* info):
        """Initialize and fill the cipher context structure with the
        appropriate values.

        """
        check_error(ccipher.mbedtls_cipher_setup(&self._ctx, info))

    cpdef _setup(self, const char* cipher_name):
        """Initialize the context with `cipher_info_from_string`."""
        if cipher_name not in get_supported_ciphers():
            raise UnsupportedCipherError("unsupported cipher: %r" % cipher_name)
        self._c_setup(ccipher.mbedtls_cipher_info_from_string(
            cipher_name))

    cpdef _get_block_size(self):
        """Returns the block size for the cipher."""
        return ccipher.mbedtls_cipher_get_block_size(&self._ctx)

    block_size = property(_get_block_size)

    cpdef _get_iv_size(self):
        """Returns the size of the cipher's IV/NONCE in bytes."""
        return ccipher.mbedtls_cipher_get_iv_size(&self._ctx)

    iv_size = property(_get_iv_size)

    cpdef _get_type(self):
        """Returns the type of the cipher."""
        return ccipher.mbedtls_cipher_get_type(&self._ctx)

    type_ = property(_get_type)

    cpdef _get_name(self):
        """Returns the name of the cipher."""
        ret = ccipher.mbedtls_cipher_get_name(&self._ctx)
        return ret if ret is not NULL else b"NONE"

    name = property(_get_name)

    cpdef _get_key_size(self):
        """Returns the size of the ciphers' key."""
        return ccipher.mbedtls_cipher_get_key_bitlen(&self._ctx) // 8

    key_size = property(_get_key_size)

    cpdef _get_operation(self):
        """Returns the operation of the given cipher."""
        return ccipher.mbedtls_cipher_get_operation(&self._ctx)

    operation = property(_get_operation)

    cdef _c_set_key(self, const unsigned char* key,
                    int key_bitlen,
                    const ccipher.mbedtls_operation_t operation):
        """Set the key to use with the given context."""
        cdef int err = ccipher.mbedtls_cipher_setkey(
            &self._ctx, key, key_bitlen, operation)
        check_error(err)

    cpdef set_enc_key(self, object key):
        """Set the encryption key."""
        # Casting read-only only buffer to typed memoryview fails, so we
        # resort to this less efficient implementation.
        cdef unsigned char[:] c_key = bytearray(key)
        self._c_set_key(&c_key[0], 8 * c_key.shape[0], OP_ENCRYPT)

    cpdef set_dec_key(self, object key):
        """Set the decryption key."""
        cdef unsigned char[:] c_key = bytearray(key)
        self._c_set_key(&c_key[0], 8 * c_key.shape[0], OP_DECRYPT)

    cpdef set_iv(self, object iv):
        """Set the initialization vector (IV)."""
        # Make sure that `c_iv` has at least size 1 before dereferencing.
        cdef unsigned char[:] c_iv = (
            bytearray(iv) if iv else bytearray(b"\x00"))
        check_error(ccipher.mbedtls_cipher_set_iv(
            &self._ctx, &c_iv[0], c_iv.shape[0]))

    cpdef reset(self):
        """Finish preparation of the context."""
        check_error(ccipher.mbedtls_cipher_reset(&self._ctx))

    cpdef update(self, object input):
        """Encrypt/decrypt using the cipher."""
        cdef unsigned char[:] c_input = bytearray(input)
        cdef size_t olen
        cdef size_t sz = c_input.shape[0] + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        cdef int err
        if not output:
            raise MemoryError()
        try:
            err = ccipher.mbedtls_cipher_update(
                &self._ctx, &c_input[0], c_input.shape[0], output, &olen)
            check_error(err)
            # We must use either an explicit loop or a list comprehension on
            # the array because a generator crashes the compiler with
            # `closures inside cpdef functions not yet supported`.
            return bytes([output[n] for n in range(olen)])
        finally:
            free(output)

    cpdef finish(self):
        """Finalization function."""
        cdef size_t olen
        cdef size_t sz = self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        cdef int err
        if not output:
            raise MemoryError()
        try:
            err = ccipher.mbedtls_cipher_finish(
                &self._ctx, output, &olen)
            check_error(err)
            # The list comprehension is required.
            return bytes([output[n] for n in range(olen)])
        finally:
            free(output)

    cpdef crypt(self, object iv, object input):
        """Generic all-in-one encryption/decryption."""
        # Make sure that `c_iv` has at least size 1 before dereferencing.
        cdef unsigned char[:] c_iv = (
            bytearray(iv) if iv else bytearray(b"\x00"))
        cdef unsigned char[:] c_input = bytearray(input)
        cdef size_t olen
        cdef size_t sz = c_input.shape[0] + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        cdef int err
        if not output:
            raise MemoryError()
        try:
            err = ccipher.mbedtls_cipher_crypt(
                &self._ctx, &c_iv[0], c_iv.shape[0],
                &c_input[0], c_input.shape[0], output, &olen)
            check_error(err)
            # The list comprehension is required.
            return bytes([output[n] for n in range(olen)])
        finally:
            free(output)


@enum.unique
class Mode(enum.Enum):

    cbc = "CBC"
    ccm = "CCM"
    cfb64 = "CFB64"
    cfb128 = "CFB128"
    ctr = "CTR"
    ecb = "ECB"
    gcm = "GCM"

    def __repr__(self):
        return str(self)


class Aes(Cipher): pass


class Camellia(Cipher): pass


class Des(Cipher): pass


class Blowfish(Cipher): pass


class Arc4(Cipher): pass
