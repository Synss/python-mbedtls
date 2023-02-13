# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Ciphers for symmetric encryption and decryption."""


from libc.stdlib cimport free, malloc

cimport mbedtls.cipher._cipher as _cipher

import enum

import mbedtls.exceptions as _exc


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
    ciphers = []
    # TODO: Typing is funky here (3.1.0 backend).  Report and fix upstream.
    cdef const mbedtls_cipher_type_t* cipher_types = (
        <const mbedtls_cipher_type_t*> _cipher.mbedtls_cipher_list()
    )
    cdef size_t n = 0
    while cipher_types[n]:
        info = _cipher.mbedtls_cipher_info_from_type(cipher_types[n])
        ciphers.append(mbedtls_cipher_info_get_name(info))
        n += 1
    return tuple(ciphers)


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
                ctx, &input[0] if input.size > 0 else NULL, input.size,
                output, &olen))
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
        assert iv.size != 0
        cdef size_t olen
        cdef size_t tag_len = 16
        cdef size_t output_len = input.size + 15 + tag_len
        cdef unsigned char* output = <unsigned char*>malloc(output_len)
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_cipher.mbedtls_cipher_auth_encrypt_ext(
                &self._enc_ctx,
                &iv[0], iv.size,
                &ad[0] if ad.size > 0 else NULL, ad.size,
                &input[0] if input.size > 0 else NULL, input.size,
                output, output_len,
                &olen, tag_len))
            assert olen <= output_len
            return output[:olen - tag_len], output[olen - tag_len:olen]
        finally:
            free(output)

    cdef _aead_decrypt(
        self,
        const unsigned char[:] iv,
        const unsigned char[:] ad,
        const unsigned char[:] input,
        size_t tag_len,
    ):
        assert iv.size != 0

        cdef size_t olen
        cdef output_len = input.size - tag_len
        cdef unsigned char* output = <unsigned char*>malloc(output_len)
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_cipher.mbedtls_cipher_auth_decrypt_ext(
                &self._dec_ctx,
                &iv[0], iv.size,
                &ad[0] if ad.size > 0 else NULL, ad.size,
                &input[0] if input.size > 0 else NULL, input.size,
                output, output_len,
                &olen, tag_len))
            return output[:olen]
        finally:
            free(output)

    def encrypt(self, const unsigned char[:] message not None):
        return self._aead_encrypt(self._iv, self._ad, message)

    def decrypt(self, bytes message not None, bytes tag not None):
        cdef const unsigned char[:] input = message + tag
        return self._aead_decrypt(self._iv, self._ad, input, len(tag))
