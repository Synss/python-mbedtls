# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

cdef extern from "mbedtls/debug.h" nogil:
    void mbedtls_debug_set_threshold(int threshold)
