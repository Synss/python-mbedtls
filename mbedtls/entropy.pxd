"""Declarations for `mbedtls/ctr_drbg.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cdef extern from "mbedtls/entropy.h":
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


cdef class Entropy:
    cdef mbedtls_entropy_context _ctx
    cpdef gather(self)
    cpdef retrieve(self, size_t length)
    cpdef update(self, data)
