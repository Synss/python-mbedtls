# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Declarations from `mbedtls/version.h`."""


cdef extern from "mbedtls/version.h" nogil:
    unsigned int mbedtls_version_get_number()
    # void mbedtls_version_get_string(char *string)
    void mbedtls_version_get_string_full(char *string)
    int mbedtls_version_check_feature(const char *feature)
