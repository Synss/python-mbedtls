# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/ecdsa.h" nogil:
    ctypedef struct mbedtls_ecdsa_context:
        mbedtls_ecp_group grp
        _mpi.mbedtls_mpi d
        mbedtls_ecp_point Q

    int MBEDTLS_ECDSA_MAX_LEN

    # mbedtls_ecp_group
    # -----------------
    # mbedtls_ecdsa_sign
    # mbedtls_ecdsa_sign_det
    # mbedtls_ecdsa_verify

    # mbedtls_ecdsa_context
    # ---------------------
    void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx)
    void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx)

    int mbedtls_ecdsa_from_keypair(
        mbedtls_ecdsa_context *ctx,
        const mbedtls_ecp_keypair *key)

    # mbedtls_ecdsa_write_signature
    # mbedtls_ecdsa_write_signature_det
    # mbedtls_ecdsa_read_signature

    int mbedtls_ecdsa_genkey(
        mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
