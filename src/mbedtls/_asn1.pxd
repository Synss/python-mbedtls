# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/asn1.h" nogil:
    cdef struct mbedtls_asn1_buf:
        int tag
        size_t len
        unsigned char *p
    cdef struct mbedtls_asn1_sequence:
        mbedtls_asn1_buf buf
        mbedtls_asn1_sequence *next
    cdef struct mbedtls_asn1_named_data:
        mbedtls_asn1_buf oid
        mbedtls_asn1_buf val
        mbedtls_asn1_named_data *next
        unsigned char next_merged
