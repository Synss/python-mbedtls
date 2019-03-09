"""Declarations for `mbedtls/pk.h`."""

# Copyright 2016, Mathias Laurin, Elaborated Networks GmbH
# Copyright 2018, Mathias Laurin

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Mathias Laurin, Elaborated Networks GmbH"
__license__ = "MIT License"


cdef extern from "mbedtls/md.h" nogil:
    ctypedef enum mbedtls_md_type_t: pass


cdef extern from "mbedtls/bignum.h" nogil:
    ctypedef struct mbedtls_mpi:
        pass


cdef extern from "mbedtls/dhm.h" nogil:
    ctypedef struct mbedtls_dhm_context:
        mbedtls_mpi P
        mbedtls_mpi G
        mbedtls_mpi X
        mbedtls_mpi GX
        mbedtls_mpi GY
        mbedtls_mpi K

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

    ctypedef struct mbedtls_ecp_curve_info:
        mbedtls_ecp_group_id grp_id
        int bit_size
        const char *name

    ctypedef struct mbedtls_ecp_point:
        mbedtls_mpi X
        mbedtls_mpi Y
        mbedtls_mpi Z

    ctypedef struct mbedtls_ecp_group:
        pass

    ctypedef struct mbedtls_ecp_keypair:
        mbedtls_ecp_group grp
        mbedtls_mpi d
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
    # mbedtls_ecp_mul
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
        mbedtls_mpi *d,
        mbedtls_ecp_point *Q,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    # mbedtls_ecp_check_pub_priv
    int mbedtls_ecp_gen_key(
        mbedtls_ecp_group_id grp_id,
        mbedtls_ecp_keypair *key,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)


cdef extern from "mbedtls/ecdh.h" nogil:
    ctypedef enum mbedtls_ecdh_side:
        MBEDTLS_ECDH_OURS
        MBEDTLS_ECDH_THEIRS

    ctypedef struct mbedtls_ecdh_context:
        mbedtls_ecp_group grp
        mbedtls_mpi d  # private key
        mbedtls_ecp_point Q  # public key
        mbedtls_ecp_point Qp  # peer's public key
        mbedtls_mpi z  # shared secret

    # mbedtls_ecp_group
    # -----------------
    int mbedtls_ecdh_gen_public(
        mbedtls_ecp_group *grp,
        mbedtls_mpi *d,
        mbedtls_ecp_point *Q,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)
    int mbedtls_ecdh_compute_shared(
        mbedtls_ecp_group *grp,
        mbedtls_mpi *z,
        const mbedtls_ecp_point *Q,
        const mbedtls_mpi *d,
        int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng)

    # mbedtls_ecdh_context
    # --------------------
    void mbedtls_ecdh_init(mbedtls_ecdh_context *ctx)
    void mbedtls_ecdh_free(mbedtls_ecdh_context *ctx)

    int mbedtls_ecdh_get_params(
        mbedtls_ecdh_context *ctx,
        const mbedtls_ecp_keypair *key,
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


cdef extern from "mbedtls/ecdsa.h" nogil:
    ctypedef struct mbedtls_ecdsa_context:
        mbedtls_ecp_group grp
        mbedtls_mpi d
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
    int mbedtls_pk_can_do(const mbedtls_pk_context *ctx,
                          mbedtls_pk_type_t type)

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


cdef class RSA(CipherBase):
    pass


cdef class ECC(CipherBase):
    cdef curve


cdef class ECPoint:
    cdef mbedtls_ecp_point _ctx


cdef class DHBase:
    cdef mbedtls_dhm_context _ctx


cdef class ECDHBase:
    cdef mbedtls_ecdh_context _ctx
    cdef curve
