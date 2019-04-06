"""Generic message digest wrapper (hash algorithm)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls._md as _md


cdef class Hmac(_md.MDBase):
    pass
