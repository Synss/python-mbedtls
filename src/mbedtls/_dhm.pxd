# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cimport mbedtls.mpi as _mpi


cdef extern from "mbedtls/dhm.h" nogil:
    ctypedef struct mbedtls_dhm_context:
        _mpi.mbedtls_mpi P
        _mpi.mbedtls_mpi G
        _mpi.mbedtls_mpi X
        _mpi.mbedtls_mpi GX
        _mpi.mbedtls_mpi GY
        _mpi.mbedtls_mpi K

    void mbedtls_dhm_init(mbedtls_dhm_context *ctx)
    void mbedtls_dhm_free(mbedtls_dhm_context *ctx)

    int mbedtls_dhm_make_params(
        mbedtls_dhm_context *ctx,
        int x_size,
        unsigned char *output, size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
    int mbedtls_dhm_make_public(
        mbedtls_dhm_context *ctx,
        int x_size,
        unsigned char *output, size_t olen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    int mbedtls_dhm_read_params(
        mbedtls_dhm_context *ctx,
        unsigned char **p,
        const unsigned char *end)
    int mbedtls_dhm_read_public(
        mbedtls_dhm_context *ctx,
        const unsigned char *input, size_t ilen)

    int mbedtls_dhm_calc_secret(
        mbedtls_dhm_context *ctx,
        unsigned char *output, size_t output_size, size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)

    # int mbedtls_dhm_parse_dhm(
    #     mbedtls_dhm_context *dhm,
    #     const unsigned char *dhmin, size_t dhminlen)
    # int mbedtls_dhm_parse_dhmfile(
    #     mbedtls_dhm_context *dhm,
    #     const char *path)
