# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Declarations from `mbedtls/platform*.h`."""


cdef extern from "mbedtls/platform_util.h" nogil:
    void mbedtls_platform_zeroize(void *buf, size_t len)
