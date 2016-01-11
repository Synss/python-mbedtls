"""Entropy accumulator wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport entropy
from libc.stdlib cimport malloc, free
import binascii
import os
from mbedtls.exceptions import check_error


cdef class Entropy:

    def __cinit__(self):
        """Initialize the context."""
        entropy.mbedtls_entropy_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        entropy.mbedtls_entropy_free(&self._ctx)

    cpdef gather(self):
        """Trigger an extra gather poll for the accumulator."""
        entropy.mbedtls_entropy_gather(&self._ctx)

    cpdef retrieve(self, size_t length):
        """Retrieve entropy from the accumulator."""
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(entropy.mbedtls_entropy_func(
                &self._ctx, output, length))
            return bytes([output[n] for n in range(length)])
        finally:
            free(output)

    cpdef update(self, data):
        """Add data to the accumulator manually."""
        cdef unsigned char[:] c_data = bytearray(data)
        check_error(entropy.mbedtls_entropy_update_manual(
            &self._ctx, &c_data[0], c_data.shape[0]))
