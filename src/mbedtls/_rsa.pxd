# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/rsa.h" nogil:
    ctypedef struct mbedtls_rsa_context:
        pass

    # mbedtls_rsa_context
    # -------------------
    # mbedtls_rsa_init
    # mbedtls_rsa_set_padding
    int mbedtls_rsa_gen_key(
        mbedtls_rsa_context *ctx,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
        unsigned int nbits, int exponent)
    int mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx)
    int mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx)
    # mbedtls_rsa_check_pub_priv
    # mbedtls_rsa_public
    # mbedtls_rsa_private
    # mbedtls_rsa_pkcs1_encrypt
    # mbedtls_rsa_rsaes_pkcs1_v15_encrypt
    # mbedtls_rsa_rsaes_oaep_encrypt
    # mbedtls_rsa_pkcs1_decrypt
    # mbedtls_rsa_rsaes_pkcs1_v15_decrypt
    # mbedtls_rsa_rsaes_oaep_decrypt
    # mbedtls_rsa_pkcs1_sign
    # mbedtls_rsa_rsassa_pkcs1_v15_sign
    # mbedtls_rsa_rsassa_pss_sign
    # mbedtls_rsa_pkcs1_verify
    # mbedtls_rsa_rsassa_pkcs1_v15_verify
    # mbedtls_rsa_rsassa_pss_verify
    # mbedtls_rsa_rsassa_pss_verify_ext
    # mbedtls_rsa_copy
    # mbedtls_rsa_free
