"""Declarations for `mbedtls/pk.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cdef extern from "mbedtls/md.h":
    ctypedef enum mbedtls_md_type_t:
        pass


cdef extern from "mbedtls/bignum.h":
    int MBEDTLS_MPI_MAX_SIZE


cdef extern from "mbedtls/ecp.h":
    ctypedef struct mbedtls_ecp_keypair:
        pass

    int MBEDTLS_ECP_MAX_BYTES


cdef extern from "mbedtls/rsa.h":
    ctypedef struct mbedtls_rsa_context:
        pass

    int mbedtls_rsa_gen_key(
        mbedtls_rsa_context *ctx,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
        unsigned int nbits, int exponent)
    int mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx)
    int mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx)


cdef extern from "mbedtls/pk.h":
    ctypedef enum mbedtls_pk_type_t:
        pass

    ctypedef struct mbedtls_pk_rsassa_pss_options:
        pass

    ctypedef struct mbedtls_pk_info_t:
        pass
    
    ctypedef struct mbedtls_pk_context:
        pass

    mbedtls_rsa_context *mbedtls_pk_rsa(const mbedtls_pk_context pk)
    mbedtls_ecp_keypair *mbedtls_pk_ec(const mbedtls_pk_context pk)
    # RSA-alt function pointer types
    const mbedtls_pk_info_t *mbedtls_pk_info_from_type(
        mbedtls_pk_type_t pk_type)
    void mbedtls_pk_init(mbedtls_pk_context *ctx)
    void mbedtls_pk_free(mbedtls_pk_context *ctx)
    int mbedtls_pk_setup(mbedtls_pk_context *ctx,
                         const mbedtls_pk_info_t *info)

    size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx)
    size_t mbedtls_pk_get_len(const mbedtls_pk_context *ctx)
    # int mbedtls_pk_can_do(const mbedtls_pk_context *ctx,
    #                       mbedtls_pk_type_t type)

    int mbedtls_pk_verify(
        mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
        const unsigned char *hash, size_t hash_len,
        const unsigned char *sig, size_t sig_len)
    # int mbedtls_pk_verify_ext(
    #     mbedtls_pk_type_t type, const void *options,
    #     mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
    #     const unsigned char *hash, size_t hash_len,
    #     const unsigned char *sig, size_t sig_len)

    int mbedtls_pk_sign(
        mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
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

    cpdef bint has_private(self)
    cpdef bint has_public(self)

    cpdef sign(self, message, digestmod=*)
    cpdef verify(self, message, signature, digestmod=*)

    cpdef encrypt(self, message)
    cpdef decrypt(self, message)

    cpdef generate(self)
    cdef bytes _write(
        self,
        int (*fun)(mbedtls_pk_context*, unsigned char*, size_t),
        size_t)
    cpdef bytes _write_private_key_der(self)
    cpdef bytes _write_public_key_der(self)
    cpdef bytes _write_private_key_pem(self)
    cpdef bytes _write_public_key_pem(self)
    cpdef _parse_private_key(self, key, password=*)
    cpdef _parse_public_key(self, key)
