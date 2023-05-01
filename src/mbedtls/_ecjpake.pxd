# SPDX-License-Identifier: MIT

cimport mbedtls._ecp as _ecp
cimport mbedtls._md as _md
cimport mbedtls.mpi as _mpi


cdef extern from "mbedtls/ecjpake.h" nogil:
    ctypedef enum mbedtls_ecjpake_role:
        MBEDTLS_ECJPAKE_CLIENT
        MBEDTLS_ECJPAKE_SERVER

    ctypedef struct mbedtls_ecjpake_context:
        _md.mbedtls_md_info_t md_info  # Hash to use
        _ecp.mbedtls_ecp_group grp     # Elliptic curve
        mbedtls_ecjpake_role role      # Are we client or server?
        int point_format               # Format for point export

        _ecp.mbedtls_ecp_point Xm1  # My public key 1
        _ecp.mbedtls_ecp_point Xm2  # My public key 2
        _ecp.mbedtls_ecp_point Xp1  # Peer public key 1
        _ecp.mbedtls_ecp_point Xp2  # Peer public key 2
        _ecp.mbedtls_ecp_point Xp   # Peer public key

        _mpi.mbedtls_mpi xm1  # My private key 1
        _mpi.mbedtls_mpi xm2  # My private key 2

        _mpi.mbedtls_mpi s    # Pre-shared secret (passphrase)

    void mbedtls_ecjpake_init(mbedtls_ecjpake_context *ctx)

    int mbedtls_ecjpake_setup(
        mbedtls_ecjpake_context *ctx,
        mbedtls_ecjpake_role role,
        _md.mbedtls_md_type_t hash,
        _ecp.mbedtls_ecp_group_id curve,
        const unsigned char *secret,
        size_t len)

    int mbedtls_ecjpake_check(const mbedtls_ecjpake_context *ctx)

    int mbedtls_ecjpake_write_round_one(
        mbedtls_ecjpake_context *ctx,
        unsigned char *buf,
        size_t len,
        size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)

    int mbedtls_ecjpake_read_round_one(
        mbedtls_ecjpake_context *ctx,
        const unsigned char *buf,
        size_t len)

    int mbedtls_ecjpake_write_round_two(
        mbedtls_ecjpake_context *ctx,
        const unsigned char *buf,
        size_t len,
        size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)

    int mbedtls_ecjpake_read_round_two(
        mbedtls_ecjpake_context *ctx,
        const unsigned char *buf,
        size_t len)

    int mbedtls_ecjpake_derive_secret(
        mbedtls_ecjpake_context *ctx,
        unsigned char *buf,
        size_t len,
        size_t *olen,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)

    void mbedtls_ecjpake_free(mbedtls_ecjpake_context *ctx)
