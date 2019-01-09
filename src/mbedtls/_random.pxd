"""Declarations for `mbedtls/ctr_drbg.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cdef extern from "mbedtls/entropy.h" nogil:
    ctypedef struct mbedtls_entropy_context:
        pass

    void mbedtls_entropy_init(mbedtls_entropy_context *ctx)
    void mbedtls_entropy_free(mbedtls_entropy_context *ctx)
    # int mbedtls_entropy_add_source(
    #     mbedtls_entropy_context *ctx,
    #     mbedtls_entropy_f_source_ptr f_source,
    #     void *p_source,
    #     size_t threshold, int strong)
    int mbedtls_entropy_gather(mbedtls_entropy_context *ctx)
    int mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
    int mbedtls_entropy_update_manual(
        mbedtls_entropy_context *ctx,
        const unsigned char *data,
        size_t len)
    # int mbedtls_entropy_write_seed_file(
    #     mbedtls_entropy_context *ctx,
    #     const char *path)
    # int mbedtls_entropy_update_seed_file(
    #     mbedtls_entropy_context *ctx,
    #     const char *path)


cdef extern from "mbedtls/ctr_drbg.h" nogil:
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


cdef class Entropy:
    cdef mbedtls_entropy_context _ctx


cdef class Random:
    cdef mbedtls_ctr_drbg_context _ctx
    cdef Entropy _entropy


# RNG for internal use only.
cdef Random default_rng()
