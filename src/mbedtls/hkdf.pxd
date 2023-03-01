# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

cimport mbedtls._md as _md


cdef extern from "mbedtls/hkdf.h" nogil:
    int mbedtls_hkdf(
        const _md.mbedtls_md_info_t *md,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *ikm, size_t ikm_len,
        const unsigned char *info, size_t info_len,
        unsigned char *okm, size_t okm_len
    )

    int mbedtls_hkdf_extract(
        const _md.mbedtls_md_info_t *md,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *ikm, size_t ikm_len,
        unsigned char *prk
    )

    int mbedtls_hkdf_expand(
        const _md.mbedtls_md_info_t *md,
        const unsigned char *prk, size_t prk_len,
        const unsigned char *info, size_t info_len,
        unsigned char *okm, size_t okm_len
    )
