# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cimport mbedtls._ecp as _ecp
cimport mbedtls.mpi as _mpi


cdef extern from "mbedtls/ecdh.h" nogil:
    ctypedef enum mbedtls_ecdh_side:
        MBEDTLS_ECDH_OURS
        MBEDTLS_ECDH_THEIRS

    ctypedef struct mbedtls_ecdh_context:
        _ecp.mbedtls_ecp_group grp
        _mpi.mbedtls_mpi d  # private key
        _ecp.mbedtls_ecp_point Q  # public key
        _ecp.mbedtls_ecp_point Qp  # peer's public key
        _mpi.mbedtls_mpi z  # shared secret

    # mbedtls_ecp_group
    # -----------------
    int mbedtls_ecdh_gen_public(
        _ecp.mbedtls_ecp_group *grp,
        _mpi.mbedtls_mpi *d,
        _ecp.mbedtls_ecp_point *Q,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    int mbedtls_ecdh_compute_shared(
        _ecp.mbedtls_ecp_group *grp,
        _mpi.mbedtls_mpi *z,
        const _ecp.mbedtls_ecp_point *Q,
        const _mpi.mbedtls_mpi *d,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)

    # mbedtls_ecdh_context
    # --------------------
    void mbedtls_ecdh_init(mbedtls_ecdh_context *ctx)
    void mbedtls_ecdh_free(mbedtls_ecdh_context *ctx)

    int mbedtls_ecdh_get_params(
        mbedtls_ecdh_context *ctx,
        const _ecp.mbedtls_ecp_keypair *key,
        mbedtls_ecdh_side side)

    int mbedtls_ecdh_make_params(
        mbedtls_ecdh_context *ctx,
        size_t *olen, unsigned char *buf, size_t blen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
    int mbedtls_ecdh_make_public(
        mbedtls_ecdh_context *ctx,
        size_t *olen, unsigned char *buf, size_t blen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_ecdh_read_params(
        mbedtls_ecdh_context *ctx,
        const unsigned char **buf, const unsigned char *end)
    int mbedtls_ecdh_read_public(
        mbedtls_ecdh_context *ctx,
        const unsigned char *buf, size_t blen)

    int mbedtls_ecdh_calc_secret(
        mbedtls_ecdh_context *ctx,
        size_t *olen, unsigned char *buf, size_t blen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
