"""Declarations from `mbedtls/md.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


cdef extern from "mbedtls/md_internal.h" nogil:
    ctypedef struct mbedtls_md_info_t:
        int block_size


cdef extern from "mbedtls/md.h" nogil:
    ctypedef enum mbedtls_md_type_t:
        pass

    ctypedef struct mbedtls_md_context_t:
        const mbedtls_md_info_t *md_info

    const int *mbedtls_md_list()
    const mbedtls_md_info_t *mbedtls_md_info_from_string(
        const char *md_name)
    # mbedtls_md_info_from_type

    void mbedtls_md_init(mbedtls_md_context_t *ctx)
    void mbedtls_md_free(mbedtls_md_context_t *ctx)

    int mbedtls_md_setup(
        mbedtls_md_context_t *ctx,
        const mbedtls_md_info_t *md_info,
        int hmac)

    int mbedtls_md_clone(mbedtls_md_context_t *dst,
                         const mbedtls_md_context_t *src)
    unsigned char mbedtls_md_get_size(const mbedtls_md_info_t *md_info)
    mbedtls_md_type_t mbedtls_md_get_type(const mbedtls_md_info_t *md_info)
    const char *mbedtls_md_get_name(const mbedtls_md_info_t *md_info)

    int mbedtls_md_starts(mbedtls_md_context_t *ctx)
    int mbedtls_md_update(
        mbedtls_md_context_t *ctx,
        const unsigned char *input,
        size_t ilen)
    int mbedtls_md_finish(
        mbedtls_md_context_t *ctx,
        unsigned char *output)
    # mbedtls_md
    # mbedtls_md_file

    int mbedtls_md_hmac_starts(
        mbedtls_md_context_t *ctx,
        const unsigned char *key,
        size_t keylen)
    int mbedtls_md_hmac_update(
        mbedtls_md_context_t *ctx,
        const unsigned char *input,
        size_t ilen)
    int mbedtls_md_hmac_finish(
        mbedtls_md_context_t *ctx,
        unsigned char *output)
    int mbedtls_md_hmac_reset(mbedtls_md_context_t *ctx)
    # mbedtls_md_hmac


cdef class MDBase:
    cdef const mbedtls_md_info_t* _info
    cdef mbedtls_md_context_t _ctx
    cdef _finish(self, const unsigned char *output)
    cpdef digest(self)
