"""Ciphers for symmetric encryption and decryption."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport ccipher
from libc.stdlib cimport malloc, free
from mbedtls.exceptions import *
import enum

__all__ = ("Mode", "Aes", "Camellia", "Des", "DesEde", "DesEde3",
           "Blowfish", "Arc4")


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


class AutoNumber(enum.Enum):

    """AutoNumber class from the `enum` doc."""

    def __new__(cls):
        value = len(cls.__members__)  # Do not add 1, we start at 0!
        obj = object.__new__(cls)
        obj._value_ = value
        return obj


class Mode(AutoNumber):

    """Enum with supported encryption modes."""

    NONE = ()
    ECB = ()
    CBC = ()
    CFB = ()
    OFB = ()
    CTR = ()
    GCM = ()
    STREAM = ()
    CCM = ()


cpdef get_supported_ciphers():
    """Return the set of ciphers supported by the generic
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


# Making the following C-level functions staticmethods of Cipher is not
# supported.  We therefore hold them at module scope.


cdef _c_setup(ccipher.mbedtls_cipher_context_t* ctx,
              char[:] cipher_name):
    """Initialize and fill the cipher context structure with the
    appropriate values.

    """
    return ccipher.mbedtls_cipher_setup(
        ctx, ccipher.mbedtls_cipher_info_from_string(&cipher_name[0]))


cdef _c_set_key(ccipher.mbedtls_cipher_context_t* ctx,
                unsigned char[:] c_key,
                ccipher.mbedtls_operation_t operation):
    """Set the key to use with the given context."""
    return ccipher.mbedtls_cipher_setkey(ctx, &c_key[0], 8 * c_key.shape[0],
                                         operation)


cdef _c_crypt(ccipher.mbedtls_cipher_context_t* ctx,
              object iv, object input):
    """Generic all-in-one encryption/decryption."""
    # Make sure that `c_iv` has at least size 1 before dereferencing.
    if not input:
        raise FullBlockExpectedError()
    cdef unsigned char[:] c_iv = (
        bytearray(iv) if iv else bytearray(b"\x00"))
    cdef unsigned char[:] c_input = bytearray(input)
    cdef size_t olen
    cdef size_t sz = c_input.shape[0] + _c_get_block_size(ctx)
    cdef unsigned char* output = <unsigned char*>malloc(
        sz * sizeof(unsigned char))
    if not output:
        raise MemoryError()
    cdef int err
    try:
        err = ccipher.mbedtls_cipher_crypt(
            ctx, &c_iv[0], c_iv.shape[0],
            &c_input[0], c_input.shape[0], output, &olen)
        # We can call `check_error` directly here because we return a
        # python object.
        check_error(err)
        # The list comprehension is required.
        return bytes([output[n] for n in range(olen)])
    finally:
        free(output)


cdef _c_get_block_size(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the block size for the cipher."""
    return ccipher.mbedtls_cipher_get_block_size(ctx)


cdef _c_get_cipher_mode(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the mode of operation of the cipher."""
    return ccipher.mbedtls_cipher_get_cipher_mode(ctx)


cdef _c_get_iv_size(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the size of the cipher's IV/NONCE in bytes."""
    return ccipher.mbedtls_cipher_get_iv_size(ctx)


cdef _c_get_type(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the type of the cipher."""
    return ccipher.mbedtls_cipher_get_type(ctx)


cdef _c_get_name(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the name of the cipher."""
    ret = ccipher.mbedtls_cipher_get_name(ctx)
    return ret if ret is not NULL else b"NONE"


cdef _c_get_key_size(ccipher.mbedtls_cipher_context_t* ctx):
    """Return the size of the ciphers' key."""
    return ccipher.mbedtls_cipher_get_key_bitlen(ctx) // 8


cdef class Cipher:

    """Wrap and encapsulate the cipher library from mbed TLS.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

        Attributes:
            block_size (int): The block size for the cipher in bytes.
            mode (Mode): The mode of operation of the cipher.
            iv_size (int): The size of the cipher's IV/NONCE in bytes.
            key_size (int): The size of the cipher's key, in bytes.

    """
    # Encapsulate two contexts to push the keys into mbedtls ASAP.
    cdef ccipher.mbedtls_cipher_context_t _enc_ctx
    cdef ccipher.mbedtls_cipher_context_t _dec_ctx
    cdef object _iv

    def __init__(self, cipher_name, key, iv):
        # Casting read-only only buffer to typed memoryview fails, so we
        # cast to bytearray.
        self._setup(cipher_name)
        self._setkey(key)
        self._iv = iv if iv else b"\x00" * self.iv_size

    def __cinit__(self):
        """Initialize a `cipher_context` (as NONE)."""
        ccipher.mbedtls_cipher_init(&self._enc_ctx)
        ccipher.mbedtls_cipher_init(&self._dec_ctx)

    def __dealloc__(self):
        """Free and clear the cipher-specific context of ctx."""
        ccipher.mbedtls_cipher_free(&self._enc_ctx)
        ccipher.mbedtls_cipher_free(&self._dec_ctx)

    cpdef _setup(self, cipher_name):
        """Initialize the context with `cipher_info_from_string`."""
        if cipher_name not in get_supported_ciphers():
            raise UnsupportedCipherError("unsupported cipher: %r" % cipher_name)
        cdef char[:] c_cipher_name = bytearray(cipher_name)
        check_error(_c_setup(&self._enc_ctx, c_cipher_name))
        check_error(_c_setup(&self._dec_ctx, c_cipher_name))

    cpdef _setkey(self, key):
        """Set the encryption/decryption key."""
        if not key:
            return
        # Casting read-only only buffer to typed memoryview fails, so we
        # cast to bytearray.
        c_key = bytearray(key)
        check_error(_c_set_key(&self._enc_ctx, c_key, ccipher.MBEDTLS_ENCRYPT))
        check_error(_c_set_key(&self._dec_ctx, c_key, ccipher.MBEDTLS_DECRYPT))

    def __str__(self):
        """Return the name of the cipher."""
        return self.name.decode("ascii")

    @property
    def block_size(self):
        """Return the block size for the cipher."""
        return _c_get_block_size(&self._enc_ctx)

    @property
    def mode(self):
        """Return the mode of operation of the cipher."""
        return Mode(_c_get_cipher_mode(&self._enc_ctx))

    @property
    def iv_size(self):
        """Return the size of the cipher's IV/NONCE in bytes."""
        return _c_get_iv_size(&self._enc_ctx)

    @property
    def _type(self):
        """Return the type of the cipher."""
        return _c_get_type(&self._enc_ctx)

    @property
    def name(self):
        """Return the name of the cipher."""
        return _c_get_name(&self._enc_ctx)

    @property
    def key_size(self):
        """Return the size of the ciphers' key."""
        return _c_get_key_size(&self._enc_ctx)

    def encrypt(self, message):
        return _c_crypt(&self._enc_ctx, self._iv, message)

    def decrypt(self, message):
        return _c_crypt(&self._dec_ctx, self._iv, message)


class Aes(Cipher):

    """Advanced Encryption Standard (AES) cipher established by the U.S.
    NIST in 2001.

    Parameters:
        bitlength (int): The size of the key, in bits.
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, bitlength, mode, key, iv=None):
        if bitlength not in {128, 192, 256}:
            raise InvalidKeyLengthError(
                "bitlength must 128, 192, or 256, got %r" % bitlength)
        if mode not in {Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR,
                        Mode.GCM, Mode.CCM}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("AES-%i-%s" % (bitlength, mode.name)).encode("ascii")
        super().__init__(name, key, iv)


class Camellia(Cipher):

    """Camellia cipher developed by Japan's Mitsubishi an NTT in 2000.

    Parameters:
        bitlength (int): The size of the key, in bits.
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, bitlength, mode, key, iv=None):
        if bitlength not in {128, 192, 256}:
            raise InvalidKeyLengthError(
                "bitlength must 128, 192, or 256, got %r" % bitlength)
        if mode not in {Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR,
                        Mode.GCM, Mode.CCM}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("CAMELLIA-%i-%s" % (bitlength, mode.name)).encode("ascii")
        super().__init__(name, key, iv)


class Des(Cipher):

    """Data Encryption Standard (DES) cipher developed by IBM
    in the 70's.

    Parameters:
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, mode, key, iv=None):
        if mode not in {Mode.ECB, Mode.CBC}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("DES-%s" % (mode.name,)).encode("ascii")
        super().__init__(name, key, iv)


class DesEde(Cipher):

    """Two-key triple DES cipher (also known as DES3, 3DES, Triple DES,
    or DES-EDE).

    Parameters:
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, mode, key, iv=None):
        if mode not in {Mode.ECB, Mode.CBC}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("DES-EDE-%s" % (mode.name,)).encode("ascii")
        super().__init__(name, key, iv)


class DesEde3(Cipher):

    """Three-key triple DES cipher (also known as DES3, 3DES,
    Triple DES, or DES-EDE3).

    Parameters:
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, mode, key, iv=None):
        if mode not in {Mode.ECB, Mode.CBC}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("DES-EDE3-%s" % (mode.name,)).encode("ascii")
        super().__init__(name, key, iv)


class Blowfish(Cipher):

    """Blowfish cipher designed by Bruce Schneier in 1993.

    Parameters:
        mode (Mode): The mode of operation of the cipher.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, mode, key, iv=None):
        if mode not in {Mode.ECB, Mode.CBC, Mode.CFB, Mode.CTR}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        name = ("BLOWFISH-%s" % (mode.name,)).encode("ascii")
        super().__init__(name, key, iv)


class Arc4(Cipher):

    """Alleged River Cipher 4 cipher (ARC4 or ARCFOUR) designed in 1987
    at RSA Security.

    Parameters:
        bitlength (int): The size of the key, in bits.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        iv (None): ARC4 does not use IV.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, bitlength, key, iv=None):
        if bitlength not in {128}:
            raise InvalidKeyLengthError(
                "bitlength must be 128, got %r" % bitlength)
        name = ("ARC4-%i" % (bitlength,)).encode("ascii")
        super().__init__(name, key, iv)
