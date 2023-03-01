# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cimport mbedtls._dhm as _dhm
cimport mbedtls._ecdh as _ecdh
cimport mbedtls._ecp as _ecp
cimport mbedtls._md as _md
cimport mbedtls._rsa as _rsa
cimport mbedtls.mpi as _mpi


cdef extern from "mbedtls/pk.h" nogil:
    ctypedef enum mbedtls_pk_type_t:
        MBEDTLS_PK_NONE=0
        MBEDTLS_PK_RSA
        MBEDTLS_PK_ECKEY
        MBEDTLS_PK_ECKEY_DH
        MBEDTLS_PK_ECDSA
        MBEDTLS_PK_RSA_ALT
        MBEDTLS_PK_RSASSA_PSS

    ctypedef struct mbedtls_pk_rsassa_pss_options:
        pass

    ctypedef struct mbedtls_pk_info_t:
        pass

    ctypedef struct mbedtls_pk_context:
        pass

    _rsa.mbedtls_rsa_context *mbedtls_pk_rsa(const mbedtls_pk_context pk)
    _ecp.mbedtls_ecp_keypair *mbedtls_pk_ec(const mbedtls_pk_context pk)
    # RSA-alt function pointer types
    const mbedtls_pk_info_t *mbedtls_pk_info_from_type(
        mbedtls_pk_type_t pk_type)
    void mbedtls_pk_init(mbedtls_pk_context *ctx)
    void mbedtls_pk_free(mbedtls_pk_context *ctx)
    int mbedtls_pk_setup(mbedtls_pk_context *ctx,
                         const mbedtls_pk_info_t *info)

    size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx)
    size_t mbedtls_pk_get_len(const mbedtls_pk_context *ctx)
    int mbedtls_pk_can_do(const mbedtls_pk_context *ctx,
                          mbedtls_pk_type_t type)

    int mbedtls_pk_verify(
        mbedtls_pk_context *ctx, _md.mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        const unsigned char *sig, size_t sig_len)
    # int mbedtls_pk_verify_ext(
    #     mbedtls_pk_type_t type, const void *options,
    #     mbedtls_pk_context *ctx, _md.mbedtls_md_type_t md_alg,
    #     const unsigned char *hash, size_t hash_len,
    #     const unsigned char *sig, size_t sig_len)

    int mbedtls_pk_sign(
        mbedtls_pk_context *ctx, _md.mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        unsigned char *sig, size_t *sig_len,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_pk_decrypt(
        mbedtls_pk_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
    int mbedtls_pk_encrypt(
        mbedtls_pk_context *ctx,
        const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen, size_t osize,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_pk_check_pair(const mbedtls_pk_context *pub,
                              const mbedtls_pk_context *prv)
    # int mbedtls_pk_debug(const mbedtls_pk_context *ctx,
    #                      mbedtls_pk_debug_item *items)
    const char * mbedtls_pk_get_name(const mbedtls_pk_context *ctx)
    mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)

    int mbedtls_pk_parse_key(
        mbedtls_pk_context *ctx,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen)
    int mbedtls_pk_parse_public_key(
        mbedtls_pk_context *ctx,
        const unsigned char *key, size_t keylen)

    # int mbedtls_pk_parse_keyfile(
    #     mbedtls_pk_context *ctx,
    #     const char *path, const char *password)
    # int mbedtls_pk_parse_public_keyfile(
    #     mbedtls_pk_context *ctx, const char *path)

    int mbedtls_pk_write_key_der(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_pubkey_der(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_pubkey_pem(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)
    int mbedtls_pk_write_key_pem(
        mbedtls_pk_context *ctx,
        unsigned char *buf, size_t size)


cdef class CipherBase:
    cdef mbedtls_pk_context _ctx


cdef class RSA(CipherBase):
    pass


cdef class ECC(CipherBase):
    cdef _curve


cdef class ECPoint:
    cdef _ecp.mbedtls_ecp_point _ctx


cdef class DHBase:
    cdef _dhm.mbedtls_dhm_context _ctx


cdef class ECDHBase:
    cdef _ecdh.mbedtls_ecdh_context _ctx
    cdef curve
