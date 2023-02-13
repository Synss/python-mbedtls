# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Declarations from `mbedtls/cipher.h`."""


cdef:
    enum: MAX_BLOCK_LENGTH = 16
    enum: MAX_IV_LENGTH = 16


cdef extern from "mbedtls/cipher.h" nogil:
    ctypedef enum mbedtls_cipher_padding_t:
        MBEDTLS_PADDING_PKCS7 = 0
        MBEDTLS_PADDING_ONE_AND_ZEROS
        MBEDTLS_PADDING_ZEROS_AND_LEN
        MBEDTLS_PADDING_ZEROS
        MBEDTLS_PADDING_NONE

    ctypedef enum mbedtls_operation_t:
        MBEDTLS_DECRYPT = 0, MBEDTLS_ENCRYPT = 1

    ctypedef enum mbedtls_cipher_type_t:
        pass

    ctypedef enum mbedtls_cipher_mode_t:
        # The numbering is standardized.
        MBEDTLS_MODE_NONE = 0,
        MBEDTLS_MODE_ECB,
        MBEDTLS_MODE_CBC,
        MBEDTLS_MODE_CFB,
        MBEDTLS_MODE_OFB,
        MBEDTLS_MODE_CTR,
        MBEDTLS_MODE_GCM,
        MBEDTLS_MODE_STREAM,
        MBEDTLS_MODE_CCM,
        MBEDTLS_MODE_XTS,
        MBEDTLS_MODE_CHACHAPOLY

    ctypedef struct mbedtls_cipher_base_t:
        pass

    ctypedef struct mbedtls_cipher_info_t:
        mbedtls_cipher_type_t type
        mbedtls_cipher_mode_t mode
        unsigned int key_bitlen
        unsigned int iv_size
        int flags
        unsigned int block_size
        const mbedtls_cipher_base_t *base

    ctypedef struct mbedtls_cipher_context_t:
        pass

    const char* mbedtls_cipher_info_get_name(const mbedtls_cipher_info_t *info)

    const int* mbedtls_cipher_list()
    const mbedtls_cipher_info_t* mbedtls_cipher_info_from_string(
        const char* cipher_name)
    const mbedtls_cipher_info_t* mbedtls_cipher_info_from_type(
        const mbedtls_cipher_type_t)
    # mbedtls_cipher_info_from_values

    void mbedtls_cipher_init(mbedtls_cipher_context_t* ctx)
    void mbedtls_cipher_free(mbedtls_cipher_context_t* ctx)

    int mbedtls_cipher_setup(
        mbedtls_cipher_context_t* ctx,
        const mbedtls_cipher_info_t* cipher_info)

    unsigned int mbedtls_cipher_get_block_size(
        const mbedtls_cipher_context_t* ctx)
    mbedtls_cipher_mode_t mbedtls_cipher_get_cipher_mode(
        const mbedtls_cipher_context_t* ctx)
    int mbedtls_cipher_get_iv_size(
        const mbedtls_cipher_context_t* ctx)
    mbedtls_cipher_type_t mbedtls_cipher_get_type(
        const mbedtls_cipher_context_t* ctx)
    const char* mbedtls_cipher_get_name(
        const mbedtls_cipher_context_t* ctx)
    int mbedtls_cipher_get_key_bitlen(
        const mbedtls_cipher_context_t* ctx)
    # mbedtls_cipher_get_operation
    int mbedtls_cipher_setkey(
        mbedtls_cipher_context_t* ctx,
        const unsigned char* key,
        int key_bitlen,
        const mbedtls_operation_t operation)
    int mbedtls_cipher_set_padding_mode(
        mbedtls_cipher_context_t* ctx,
        mbedtls_cipher_padding_t mode
    )
    int mbedtls_cipher_set_iv(
        mbedtls_cipher_context_t* ctx,
        const unsigned char *iv, size_t iv_len
    )
    int mbedtls_cipher_reset(mbedtls_cipher_context_t* ctx)
    int mbedtls_cipher_update_ad(
        mbedtls_cipher_context_t* ctx,
        const unsigned char *ad, size_t ad_len)
    int mbedtls_cipher_update(
        mbedtls_cipher_context_t* ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen)
    int mbedtls_cipher_finish(
        mbedtls_cipher_context_t* ctx,
        unsigned char *output, size_t *olen)

    # mbedtls_cipher_write_tag
    # mbedtls_cipher_check_tag

    # int mbedtls_cipher_crypt(
    #     mbedtls_cipher_context_t* ctx,
    #     const unsigned char* iv, size_t iv_len,
    #     const unsigned char* input, size_t ilen,
    #     unsigned char* output, size_t* olen)

    int mbedtls_cipher_auth_encrypt_ext(
        mbedtls_cipher_context_t* ctx,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ad, size_t ad_len,
        const unsigned char* input, size_t ilen,
        unsigned char* output, size_t output_len,
        size_t* olen, size_t tag_len)

    int mbedtls_cipher_auth_decrypt_ext(
        mbedtls_cipher_context_t* ctx,
        const unsigned char* iv, size_t iv_len,
        const unsigned char* ad, size_t ad_len,
        const unsigned char* input, size_t ilen,
        unsigned char* output, size_t output_len,
        size_t* olen, size_t tag_len)


cdef class _CipherBase:
    # Encapsulate two contexts to push the keys into mbedtls ASAP.
    cdef mbedtls_cipher_context_t _enc_ctx
    cdef mbedtls_cipher_context_t _dec_ctx


cdef class Cipher(_CipherBase):
    cdef _crypt(
        self,
        mbedtls_cipher_context_t *ctx,
        const unsigned char[:] input,
    )


cdef class AEADCipher(_CipherBase):
    cdef const unsigned char[:] _ad
    cdef const unsigned char[:] _iv
    cdef _aead_encrypt(
        self,
        const unsigned char[:] iv,
        const unsigned char[:] ad,
        const unsigned char[:] input,
    )
    cdef _aead_decrypt(
        self,
        const unsigned char[:] iv,
        const unsigned char[:] ad,
        const unsigned char[:] input,
        size_t tag_len,
    )
