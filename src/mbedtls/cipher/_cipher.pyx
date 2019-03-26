"""Ciphers for symmetric encryption and decryption."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport mbedtls.cipher._cipher as _cipher
from libc.stdlib cimport malloc, free

try:
    from contextlib import suppress
except ImportError:
    # Python 2.7
    from contextlib2 import suppress

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
    b"ARIA-128-ECB",
    b"ARIA-192-ECB",
    b"ARIA-256-ECB",
    b"ARIA-128-CBC",
    b"ARIA-192-CBC",
    b"ARIA-256-CBC",
    b"ARIA-128-CFB128",
    b"ARIA-192-CFB128",
    b"ARIA-256-CFB128",
    b"ARIA-128-CTR",
    b"ARIA-192-CTR",
    b"ARIA-256-CTR",
    b"ARIA-128-GCM",
    b"ARIA-192-GCM",
    b"ARIA-256-GCM",
    b"ARIA-128-CCM",
    b"ARIA-192-CCM",
    b"ARIA-256-CCM",
    b"AES-128-OFB",
    b"AES-192-OFB",
    b"AES-256-OFB",
    b"AES-128-XTS",
    b"AES-256-XTS",
    b"CHACHA20",
    b"CHACHA20-POLY1305",
)


MODE_ECB = _cipher.MBEDTLS_MODE_ECB
MODE_CBC = _cipher.MBEDTLS_MODE_CBC
MODE_CFB = _cipher.MBEDTLS_MODE_CFB
MODE_OFB = _cipher.MBEDTLS_MODE_OFB
MODE_CTR = _cipher.MBEDTLS_MODE_CTR
MODE_GCM = _cipher.MBEDTLS_MODE_GCM
MODE_STREAM = _cipher.MBEDTLS_MODE_STREAM
MODE_CCM = _cipher.MBEDTLS_MODE_CCM
MODE_XTS = _cipher.MBEDTLS_MODE_XTS
MODE_CHACHAPOLY = _cipher.MBEDTLS_MODE_CHACHAPOLY


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
        8: "CCM",
        9: "XTS",
        10: "CHACHAPOLY"
    }[mode]


__all__ = (
    "MODE_ECB", "MODE_CBC", "MODE_CFB", "MODE_OFB", "MODE_CTR", "MODE_GCM",
    "MODE_STREAM", "MODE_CCM", "MODE_XTS", "MODE_CHACHAPOLY", "Cipher",
    "AEADCipher"
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
        with suppress(KeyError):
            ciphers.add(cipher_lookup[cipher_types[n]])
        n += 1
    return ciphers


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
    def __init__(self,
                 cipher_name,
                 const unsigned char[:] key,
                 mode,
                 const unsigned char[:] iv not None):
        if mode in {MODE_CBC, MODE_CFB} and iv.size == 0:
            raise ValueError("mode requires an IV")
        if cipher_name not in get_supported_ciphers():
            raise TLSError(msg="unsupported cipher: %r" % cipher_name)

        check_error(_cipher.mbedtls_cipher_setup(
            &self._enc_ctx,
            _cipher.mbedtls_cipher_info_from_string(cipher_name)))
        check_error(_cipher.mbedtls_cipher_setup(
            &self._dec_ctx,
            _cipher.mbedtls_cipher_info_from_string(cipher_name)))

        if key is not None:
            check_error(_cipher.mbedtls_cipher_setkey(
                &self._enc_ctx, &key[0], 8 * key.size,
                _cipher.MBEDTLS_ENCRYPT))
            check_error(_cipher.mbedtls_cipher_setkey(
                &self._dec_ctx, &key[0], 8 * key.size,
                _cipher.MBEDTLS_DECRYPT))

        if iv is None:
            self._iv = b"\x00" * max(1, self.iv_size)
        elif iv.size == 0:
            self._iv = b"\x00" * max(1, self.iv_size)
        else:
            self._iv = iv

    def __cinit__(self):
        """Initialize a `cipher_context` (as NONE)."""
        _cipher.mbedtls_cipher_init(&self._enc_ctx)
        _cipher.mbedtls_cipher_init(&self._dec_ctx)

    def __dealloc__(self):
        """Free and clear the cipher-specific context of ctx."""
        _cipher.mbedtls_cipher_free(&self._enc_ctx)
        _cipher.mbedtls_cipher_free(&self._dec_ctx)

    def __str__(self):
        """Return the name of the cipher."""
        return self.name.decode("ascii")

    @property
    def block_size(self):
        """Return the block size for the cipher."""
        return _cipher.mbedtls_cipher_get_block_size(&self._enc_ctx)

    @property
    def mode(self):
        """Return the mode of operation of the cipher."""
        return _cipher.mbedtls_cipher_get_cipher_mode(&self._enc_ctx)

    @property
    def iv_size(self):
        """Return the size of the cipher's IV/NONCE in bytes."""
        return _cipher.mbedtls_cipher_get_iv_size(&self._enc_ctx)

    @property
    def _type(self):
        """Return the type of the cipher."""
        return _cipher.mbedtls_cipher_get_type(&self._enc_ctx)

    @property
    def name(self):
        """Return the name of the cipher."""
        ret = _cipher.mbedtls_cipher_get_name(&self._enc_ctx)
        return ret if ret is not NULL else b"NONE"

    @property
    def key_size(self):
        """Return the size of the ciphers' key."""
        return _cipher.mbedtls_cipher_get_key_bitlen(&self._enc_ctx) // 8

    cdef _crypt(self, 
                const unsigned char[:] iv,
                const unsigned char[:] input,
                const _cipher.mbedtls_operation_t operation):
        """Generic all-in-one encryption/decryption."""
        if input.size == 0:
            check_error(-0x6280)  # Raise full block expected error.
        assert iv.size != 0
        cdef size_t olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            # We can call `check_error` directly here because we return a
            # python object.
            check_error(_cipher.mbedtls_cipher_crypt(
                &self._enc_ctx if operation is _cipher.MBEDTLS_ENCRYPT else
                &self._dec_ctx,
                &iv[0], iv.size,
                &input[0], input.size, output, &olen))
            return bytes(output[:olen])
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        return self._crypt(self._iv, message, _cipher.MBEDTLS_ENCRYPT)

    def decrypt(self, const unsigned char[:] message not None):
        return self._crypt(self._iv, message, _cipher.MBEDTLS_DECRYPT)


cdef class AEADCipher(Cipher):
    def __init__(self,
                 cipher_name,
                 const unsigned char[:] key,
                 mode,
                 const unsigned char[:] iv not None,
                 const unsigned char[:] ad not None):
        super().__init__(cipher_name, key, mode, iv)
        self._ad = ad

    cdef _aead_encrypt(self,
                const unsigned char[:] iv,
                const unsigned char[:] ad,
                const unsigned char[:] input):
        if input.size == 0:
            check_error(-0x6280)  # Raise full block expected error.
        assert iv.size != 0
        cdef size_t olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char tag[16];
        assert sizeof(tag) == 16
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            if ad.size:
                pad = <const unsigned char*> &ad[0]
            else:
                pad = NULL
            check_error(_cipher.mbedtls_cipher_auth_encrypt(
                &self._enc_ctx,
                &iv[0], iv.size, pad, ad.size,
                &input[0], input.size, output, &olen,
                tag, sizeof(tag)))
            return bytes(output[:olen]), bytes(tag[:16])
        finally:
            free(output)

    cdef _aead_decrypt(self,
                const unsigned char[:] iv,
                const unsigned char[:] ad,
                const unsigned char[:] input,
                const unsigned char[:] tag):
        if input.size == 0:
            check_error(-0x6280)  # Raise full block expected error.
        assert iv.size != 0
        assert tag.size == 16
        cdef size_t olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            if ad.size:
                pad = <const unsigned char*> &ad[0]
            else:
                pad = NULL
            check_error(_cipher.mbedtls_cipher_auth_decrypt(
                &self._dec_ctx,
                &iv[0], iv.size, pad, ad.size,
                &input[0], input.size, output, &olen,
                &tag[0], tag.size))
            return bytes(output[:olen])
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        return self._aead_encrypt(self._iv, self._ad, message)

    def decrypt(self, const unsigned char[:] message not None,
                const unsigned char[:] tag not None):
        return self._aead_decrypt(self._iv, self._ad, message, tag)
