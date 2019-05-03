"""Declarations from `mbedtls/platform*.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/platform_util.h" nogil:
    void mbedtls_platform_zeroize(void *buf, size_t len)
