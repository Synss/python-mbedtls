# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Ciphers for symmetric encryption and decryption."""


from libc.stdlib cimport free, malloc

cimport mbedtls.cipher._cipher as _cipher

import enum
from contextlib import suppress

import mbedtls.exceptions as _exc

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
    b"AES-128-CTR",
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


@enum.unique
class Mode(enum.Enum):
    ECB = _cipher.MBEDTLS_MODE_ECB
    CBC = _cipher.MBEDTLS_MODE_CBC
    CFB = _cipher.MBEDTLS_MODE_CFB
    OFB = _cipher.MBEDTLS_MODE_OFB
    CTR = _cipher.MBEDTLS_MODE_CTR
    GCM = _cipher.MBEDTLS_MODE_GCM
    STREAM = _cipher.MBEDTLS_MODE_STREAM
    CCM = _cipher.MBEDTLS_MODE_CCM
    XTS = _cipher.MBEDTLS_MODE_XTS
    CHACHAPOLY = _cipher.MBEDTLS_MODE_CHACHAPOLY


cpdef get_supported_ciphers():
    """Return the ciphers supported by the generic cipher module."""
    cipher_lookup = {n: v for n, v in enumerate(CIPHER_NAME)}
    cdef const int* cipher_types = _cipher.mbedtls_cipher_list()
    cdef size_t n = 0
    ciphers = set()
    while cipher_types[n]:
        with suppress(KeyError):
            ciphers.add(cipher_lookup[cipher_types[n]])
        n += 1
    return ciphers


cdef class _CipherBase:

    """Wrap and encapsulate the cipher library from mbed TLS.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.

        Attributes:
            block_size (int): The block size for the cipher in bytes.
            mode (int): The mode of operation of the cipher.
            iv_size (int): The size of the cipher's IV/NONCE in bytes.
            key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(
        self,
        cipher_name,
        const unsigned char[:] key,
        mode,
        const unsigned char[:] iv not None
    ):
        mode = Mode(mode)
        if mode in {Mode.CBC, Mode.CFB} and iv.size == 0:
            raise ValueError("mode requires an IV")
        if cipher_name not in get_supported_ciphers():
            raise NotImplementedError("unsupported cipher: %r" % cipher_name)

        _exc.check_error(_cipher.mbedtls_cipher_setup(
            &self._enc_ctx,
            _cipher.mbedtls_cipher_info_from_string(cipher_name)))
        _exc.check_error(_cipher.mbedtls_cipher_setup(
            &self._dec_ctx,
            _cipher.mbedtls_cipher_info_from_string(cipher_name)))
        # Remove the default padding for the modes that support it and
        # ignore possible errors caused by a cipher mode that doesn't.
        #
        # Note: Padding is only supported by CBC (mbedtls 2.16.12).
        _cipher.mbedtls_cipher_set_padding_mode(
            &self._enc_ctx, _cipher.MBEDTLS_PADDING_NONE)
        _cipher.mbedtls_cipher_set_padding_mode(
            &self._dec_ctx, _cipher.MBEDTLS_PADDING_NONE)

        if key is not None:
            _exc.check_error(_cipher.mbedtls_cipher_setkey(
                &self._enc_ctx, &key[0], 8 * key.size,
                _cipher.MBEDTLS_ENCRYPT))
            _exc.check_error(_cipher.mbedtls_cipher_setkey(
                &self._dec_ctx, &key[0], 8 * key.size,
                _cipher.MBEDTLS_DECRYPT))

        _exc.check_error(_cipher.mbedtls_cipher_set_iv(
            &self._enc_ctx, &iv[0] if iv.size else NULL, iv.size))
        _exc.check_error(_cipher.mbedtls_cipher_set_iv(
            &self._dec_ctx, &iv[0] if iv.size else NULL, iv.size))

    def __cinit__(self):
        """Initialize a `cipher_context` (as NONE)."""
        _cipher.mbedtls_cipher_init(&self._enc_ctx)
        _cipher.mbedtls_cipher_init(&self._dec_ctx)

    def __dealloc__(self):
        """Free and clear the cipher-specific context of ctx."""
        _cipher.mbedtls_cipher_free(&self._enc_ctx)
        _cipher.mbedtls_cipher_free(&self._dec_ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

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
        return Mode(_cipher.mbedtls_cipher_get_cipher_mode(&self._enc_ctx))

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

    def encrypt(self, const unsigned char[:] message not None):
        raise NotImplementedError

    def decrypt(self, const unsigned char[:] message not None):
        raise NotImplementedError


cdef class Cipher(_CipherBase):
    cdef _crypt(self,
                _cipher.mbedtls_cipher_context_t *ctx,
                const unsigned char[:] input):
        if input.size == 0:
            _exc.check_error(-0x6280)  # Raise full block expected error.
        cdef size_t olen
        cdef size_t finish_olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_cipher.mbedtls_cipher_reset(ctx))
            _exc.check_error(_cipher.mbedtls_cipher_update(
                ctx, &input[0], input.size, output, &olen))
            err = _cipher.mbedtls_cipher_finish(
                ctx, output + olen, &finish_olen
            )
            if err == -0x6280:
                raise ValueError("expected a full block")
            _exc.check_error(err)
            return output[:olen + finish_olen]
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        return self._crypt(&self._enc_ctx, message)

    def decrypt(self, const unsigned char[:] message not None):
        return self._crypt(&self._dec_ctx, message)


cdef class AEADCipher(_CipherBase):
    def __init__(self,
                 cipher_name,
                 const unsigned char[:] key,
                 mode,
                 const unsigned char[:] iv not None,
                 const unsigned char[:] ad not None):
        super().__init__(cipher_name, key, mode, iv)
        self._iv = iv
        self._ad = ad

    cdef _aead_encrypt(
        self,
        const unsigned char[:] iv,
        const unsigned char[:] ad,
        const unsigned char[:] input
    ):
        if input.size == 0:
            _exc.check_error(-0x6280)  # Raise full block expected error.
        assert iv.size != 0
        cdef size_t olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char tag[16]
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            pad = <const unsigned char*> (&ad[0] if ad.size else NULL)
            _exc.check_error(_cipher.mbedtls_cipher_auth_encrypt(
                &self._enc_ctx,
                &iv[0], iv.size, pad, ad.size,
                &input[0], input.size, output, &olen,
                tag, sizeof(tag)))
            return output[:olen], tag[:16]
        finally:
            free(output)

    cdef _aead_decrypt(
        self,
        const unsigned char[:] iv,
        const unsigned char[:] ad,
        const unsigned char[:] input,
        const unsigned char[:] tag,
    ):
        if input.size == 0:
            _exc.check_error(-0x6280)  # Raise full block expected error.
        assert iv.size != 0
        assert tag.size == 16

        cdef const unsigned char *pad
        if ad.size == 0:
            pad = NULL
        else:
            pad = &ad[0]

        cdef size_t olen
        cdef size_t sz = input.size + self.block_size
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_cipher.mbedtls_cipher_auth_decrypt(
                &self._dec_ctx,
                &iv[0], iv.size, pad, ad.size,
                &input[0], input.size, output, &olen,
                &tag[0], tag.size))
            return output[:olen]
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        return self._aead_encrypt(self._iv, self._ad, message)

    def decrypt(self, const unsigned char[:] message not None,
                const unsigned char[:] tag not None):
        return self._aead_decrypt(self._iv, self._ad, message, tag)
