"""Declarations from `mbedtls/error.h`."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef extern from "mbedtls/error.h" nogil:
    void mbedtls_strerror(int errnum, char *buffer, size_t buflen)
