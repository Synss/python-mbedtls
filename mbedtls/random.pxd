"""Declarations for `mbedtls/ctr_drbg.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cdef extern from "mbedtls/ctr_drbg.h":
    ctypedef struct mbedtls_ctr_drbg_context:
        pass

    void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx)
    int mbedtls_ctr_drbg_seed(
        mbedtls_ctr_drbg_context *ctx,
        int (*f_entropy)(void *, unsigned char *, size_t),
        void *p_entropy,
        const unsigned char *custom,
        size_t len)
    void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx)

    # void mbedtls_ctr_drbg_set_prediction_resistance(
    #     mbedtls_ctr_drbg_context *ctx,
    #     int resistance)
    # void mbedtls_ctr_drbg_set_entropy_len(
    #     mbedtls_ctr_drbg_context *ctx,
    #     size_t len)
    # void mbedtls_ctr_drbg_set_reseed_interval(
    #     mbedtls_ctr_drbg_context *ctx,
    #     int interval)

    int mbedtls_ctr_drbg_reseed(
        mbedtls_ctr_drbg_context *ctx,
        const unsigned char *additional, size_t len)
    void mbedtls_ctr_drbg_update(
        mbedtls_ctr_drbg_context *ctx,
        const unsigned char *additional, size_t add_len)
    # int mbedtls_ctr_drbg_random_with_add(
    #     void *p_rng,
    #     unsigned char *output, size_t output_len,
    #     const unsigned char *additional, size_t add_len)
    int mbedtls_ctr_drbg_random(
        void *p_rng,
        unsigned char *output, size_t output_len)
    # int mbedtls_ctr_drbg_write_seed_file(
    #     mbedtls_ctr_drbg_context *ctx, const char *path)
    # int mbedtls_ctr_drbg_update_seed_file(
    #     mbedtls_ctr_drbg_context *ctx, const char *path)
