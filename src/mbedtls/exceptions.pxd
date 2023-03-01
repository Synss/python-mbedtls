# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/error.h" nogil:
    void mbedtls_strerror(int errnum, char *buffer, size_t buflen)
