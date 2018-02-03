"""Ciphers for symmetric encryption and decryption."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport _cipher
from libc.stdlib cimport malloc, free
from mbedtls.exceptions import *


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


MODE_ECB = _cipher.MBEDTLS_MODE_ECB
MODE_CBC = _cipher.MBEDTLS_MODE_CBC
MODE_CFB = _cipher.MBEDTLS_MODE_CFB
MODE_OFB = _cipher.MBEDTLS_MODE_OFB
MODE_CTR = _cipher.MBEDTLS_MODE_CTR
MODE_GCM = _cipher.MBEDTLS_MODE_GCM
MODE_STREAM = _cipher.MBEDTLS_MODE_STREAM
MODE_CCM = _cipher.MBEDTLS_MODE_CCM


__supported_modes = {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_CTR,
    MODE_GCM,
    MODE_CCM
}


cpdef _get_mode_name(mode):
    return {
        1: "ECB",
        2: "CBC",
        3: "CFB",
        4: "OFB",
        5: "CTR",
        6: "GCM",
        7: "STREAM",
        8: "CCM"
    }[mode]


__all__ = (
    "MODE_ECB", "MODE_CBC", "MODE_CFB", "MODE_CTR", "MODE_GCM", "MODE_CCM",
    "Cipher"
)


cpdef get_supported_ciphers():
    """Return the set of ciphers supported by the generic
    cipher module.

    """
    cipher_lookup = {n: v for n, v in enumerate(CIPHER_NAME)}
    cdef const int* cipher_types = _cipher.mbedtls_cipher_list()
    cdef size_t n = 0
    ciphers = set()
    while cipher_types[n]:
        ciphers.add(cipher_lookup[cipher_types[n]])
        n += 1
    return ciphers


# Making the following C-level functions staticmethods of Cipher is not
# supported.  We therefore hold them at module scope.


cdef _c_setup(_cipher.mbedtls_cipher_context_t* ctx,
              char[:] cipher_name):
    """Initialize and fill the cipher context structure with the
    appropriate values.

    """
    return _cipher.mbedtls_cipher_setup(
        ctx, _cipher.mbedtls_cipher_info_from_string(&cipher_name[0]))


cdef _c_set_key(_cipher.mbedtls_cipher_context_t* ctx,
                unsigned char[:] c_key,
                _cipher.mbedtls_operation_t operation):
    """Set the key to use with the given context."""
    return _cipher.mbedtls_cipher_setkey(ctx, &c_key[0], 8 * c_key.shape[0],
                                         operation)


cdef _c_crypt(_cipher.mbedtls_cipher_context_t* ctx,
              object iv, object input):
    """Generic all-in-one encryption/decryption."""
    # Make sure that `c_iv` has at least size 1 before dereferencing.
    if not input:
        check_error(-0x6280)  # Raise full block expected error.
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
        err = _cipher.mbedtls_cipher_crypt(
            ctx, &c_iv[0], c_iv.shape[0],
            &c_input[0], c_input.shape[0], output, &olen)
        # We can call `check_error` directly here because we return a
        # python object.
        check_error(err)
        return bytes(output[:olen])
    finally:
        free(output)


cdef _c_get_block_size(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the block size for the cipher."""
    return _cipher.mbedtls_cipher_get_block_size(ctx)


cdef _c_get_cipher_mode(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the mode of operation of the cipher."""
    return _cipher.mbedtls_cipher_get_cipher_mode(ctx)


cdef _c_get_iv_size(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the size of the cipher's IV/NONCE in bytes."""
    return _cipher.mbedtls_cipher_get_iv_size(ctx)


cdef _c_get_type(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the type of the cipher."""
    return _cipher.mbedtls_cipher_get_type(ctx)


cdef _c_get_name(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the name of the cipher."""
    ret = _cipher.mbedtls_cipher_get_name(ctx)
    return ret if ret is not NULL else b"NONE"


cdef _c_get_key_size(_cipher.mbedtls_cipher_context_t* ctx):
    """Return the size of the ciphers' key."""
    return _cipher.mbedtls_cipher_get_key_bitlen(ctx) // 8


cdef class Cipher:

    """Wrap and encapsulate the cipher library from mbed TLS.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

        Attributes:
            block_size (int): The block size for the cipher in bytes.
            mode (int): The mode of operation of the cipher.
            iv_size (int): The size of the cipher's IV/NONCE in bytes.
            key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, cipher_name, key, mode, iv):
        if mode in {MODE_CBC, MODE_CFB} and not iv:
            raise ValueError("mode requires an IV")
        self._setup(cipher_name)
        self._setkey(key)
        self._iv = iv if iv else b"\x00" * self.iv_size

    def __cinit__(self):
        """Initialize a `cipher_context` (as NONE)."""
        _cipher.mbedtls_cipher_init(&self._enc_ctx)
        _cipher.mbedtls_cipher_init(&self._dec_ctx)

    def __dealloc__(self):
        """Free and clear the cipher-specific context of ctx."""
        _cipher.mbedtls_cipher_free(&self._enc_ctx)
        _cipher.mbedtls_cipher_free(&self._dec_ctx)

    cpdef _setup(self, cipher_name):
        """Initialize the context with `cipher_info_from_string`."""
        if cipher_name not in get_supported_ciphers():
            raise CipherError(-1, "unsupported cipher: %r" % cipher_name)
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
        check_error(_c_set_key(&self._enc_ctx, c_key, _cipher.MBEDTLS_ENCRYPT))
        check_error(_c_set_key(&self._dec_ctx, c_key, _cipher.MBEDTLS_DECRYPT))

    def __str__(self):
        """Return the name of the cipher."""
        return self.name.decode("ascii")

    property block_size:
        """Return the block size for the cipher."""
        def __get__(self):
            return _c_get_block_size(&self._enc_ctx)

    property mode:
        """Return the mode of operation of the cipher."""
        def __get__(self):
            return _c_get_cipher_mode(&self._enc_ctx)

    property iv_size:
        """Return the size of the cipher's IV/NONCE in bytes."""
        def __get__(self):
            return _c_get_iv_size(&self._enc_ctx)

    property _type:
        """Return the type of the cipher."""
        def __get__(self):
            return _c_get_type(&self._enc_ctx)

    property name:
        """Return the name of the cipher."""
        def __get__(self):
            return _c_get_name(&self._enc_ctx)

    property key_size:
        """Return the size of the ciphers' key."""
        def __get__(self):
            return _c_get_key_size(&self._enc_ctx)

    def encrypt(self, message):
        return _c_crypt(&self._enc_ctx, self._iv, message)

    def decrypt(self, message):
        return _c_crypt(&self._dec_ctx, self._iv, message)
