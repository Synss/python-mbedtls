# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

cimport mbedtls.mpi as _mpi


cdef extern from "mbedtls/ecp.h" nogil:
    ctypedef enum mbedtls_ecp_group_id:
        MBEDTLS_ECP_DP_NONE = 0,
        MBEDTLS_ECP_DP_SECP192R1
        MBEDTLS_ECP_DP_SECP224R1
        MBEDTLS_ECP_DP_SECP256R1
        MBEDTLS_ECP_DP_SECP384R1
        MBEDTLS_ECP_DP_SECP521R1
        MBEDTLS_ECP_DP_BP256R1
        MBEDTLS_ECP_DP_BP384R1
        MBEDTLS_ECP_DP_BP512R1
        MBEDTLS_ECP_DP_CURVE25519
        MBEDTLS_ECP_DP_SECP192K1
        MBEDTLS_ECP_DP_SECP224K1
        MBEDTLS_ECP_DP_SECP256K1
        MBEDTLS_ECP_DP_CURVE448

    ctypedef enum mbedtls_ecp_curve_type:
        MBEDTLS_ECP_TYPE_NONE = 0
        MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS
        MBEDTLS_ECP_TYPE_MONTGOMERY

    ctypedef struct mbedtls_ecp_curve_info:
        mbedtls_ecp_group_id grp_id
        int bit_size
        const char *name

    ctypedef struct mbedtls_ecp_point:
        _mpi.mbedtls_mpi X
        _mpi.mbedtls_mpi Y
        _mpi.mbedtls_mpi Z

    ctypedef struct mbedtls_ecp_group:
        mbedtls_ecp_group_id id
        _mpi.mbedtls_mpi P
        _mpi.mbedtls_mpi A
        _mpi.mbedtls_mpi B
        mbedtls_ecp_point G
        _mpi.mbedtls_mpi N
        size_t pbits
        size_t nbits
        unsigned int h
        int (*modp)(_mpi.mbedtls_mpi *)
        int (*t_pre)(mbedtls_ecp_point *, void *)
        int (*t_post)(mbedtls_ecp_point *, void *)
        void *t_data
        mbedtls_ecp_point *T
        size_t T_size

    ctypedef struct mbedtls_ecp_keypair:
        mbedtls_ecp_group grp
        _mpi.mbedtls_mpi d
        mbedtls_ecp_point Q

    int MBEDTLS_ECP_MAX_BYTES
    int MBEDTLS_ECP_PF_UNCOMPRESSED

    # Free functions
    # --------------
    const mbedtls_ecp_curve_info* mbedtls_ecp_curve_list()
    # mbedtls_ecp_grp_id_list
    # mbedtls_ecp_curve_info_from_grp_id
    # mbedtls_ecp_curve_info_from_tls_id
    # mbedtls_ecp_curve_info_from_name
    mbedtls_ecp_curve_type mbedtls_ecp_get_type(
        const mbedtls_ecp_group *grp
    )

    # mbedtls_ecp_point
    # -----------------
    void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
    void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
    int mbedtls_ecp_copy(
        mbedtls_ecp_point *P,
        const mbedtls_ecp_point *Q)
    # mbedtls_ecp_set_zero
    int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
    int mbedtls_ecp_point_cmp(
        const mbedtls_ecp_point *P,
        const mbedtls_ecp_point *Q)
    # mbedtls_ecp_point_read_string

    # mbedtls_ecp_group
    # -----------------
    void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
    void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
    int mbedtls_ecp_group_copy(
        mbedtls_ecp_group *dst,
        const mbedtls_ecp_group *src)

    int mbedtls_ecp_point_write_binary(
        const mbedtls_ecp_group *grp,
        const mbedtls_ecp_point *P,
        int format, size_t *olen, unsigned char *buf, size_t buflen)
    int mbedtls_ecp_point_read_binary(
        const mbedtls_ecp_group *grp,
        mbedtls_ecp_point *P,
        const unsigned char *buf, size_t ilen)

    # mbedtls_ecp_tls_read_point
    # mbedtls_ecp_tls_write_point

    int mbedtls_ecp_group_load(
        mbedtls_ecp_group *grp,
        mbedtls_ecp_group_id index)

    # mbedtls_ecp_tls_read_group
    # mbedtls_ecp_tls_write_group
    int mbedtls_ecp_mul(
        mbedtls_ecp_group *grp,
        mbedtls_ecp_point *R,
        const _mpi.mbedtls_mpi *m,
        const mbedtls_ecp_point *P,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    # mbedtls_ecp_muladd
    # mbedtls_ecp_check_pubkey
    # mbedtls_ecp_check_privkey

    # mbedtls_ecp_keypair
    # -------------------
    void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
    void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
    # mbedtls_ecp_gen_keypair_base
    int mbedtls_ecp_gen_keypair(
        mbedtls_ecp_group *grp,
        _mpi.mbedtls_mpi *d,
        mbedtls_ecp_point *Q,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    # mbedtls_ecp_check_pub_priv
    int mbedtls_ecp_gen_key(
        mbedtls_ecp_group_id grp_id,
        mbedtls_ecp_keypair *key,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
