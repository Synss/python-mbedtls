"""Random number generator (RNG) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport random


cdef class Random:

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_ctr_drbg_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        random.mbedtls_ctr_drbg_free(&self._ctx)
