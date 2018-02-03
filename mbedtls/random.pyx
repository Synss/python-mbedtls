"""Random number generator (RNG) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free
cimport random
import binascii
from mbedtls.exceptions import check_error


cdef class Entropy:

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_entropy_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        random.mbedtls_entropy_free(&self._ctx)

    cpdef gather(self):
        """Trigger an extra gather poll for the accumulator."""
        random.mbedtls_entropy_gather(&self._ctx)

    cpdef retrieve(self, size_t length):
        """Retrieve entropy from the accumulator."""
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(random.mbedtls_entropy_func(
                &self._ctx, output, length))
            return bytes(output[:length])
        finally:
            free(output)

    cpdef update(self, data):
        """Add data to the accumulator manually."""
        cdef unsigned char[:] c_data = bytearray(data)
        check_error(random.mbedtls_entropy_update_manual(
            &self._ctx, &c_data[0], c_data.shape[0]))


cdef class Random:

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_ctr_drbg_init(&self._ctx)
        self._entropy = Entropy()
        check_error(random.mbedtls_ctr_drbg_seed(
            &self._ctx,
            &random.mbedtls_entropy_func, &self._entropy._ctx,
            NULL, 0))

    def __dealloc__(self):
        """Free and clear the context."""
        random.mbedtls_ctr_drbg_free(&self._ctx)

    cpdef reseed(self):
        """Reseed the RNG."""
        check_error(random.mbedtls_ctr_drbg_reseed(&self._ctx, NULL, 0))

    cpdef update(self, data):
        """Update state with additional data."""
        cdef unsigned char[:] c_data = bytearray(data)
        random.mbedtls_ctr_drbg_update(&self._ctx, &c_data[0], c_data.shape[0])

    cpdef token_bytes(self, length):
        """Returns `length` random bytes."""
        cdef size_t sz = length
        cdef unsigned char* output = <unsigned char*>malloc(
            sz * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(random.mbedtls_ctr_drbg_random(
                &self._ctx, output, sz))
            return bytes(output[:sz])
        finally:
            free(output)

    cpdef token_hex(self, length):
        """Same as `token_bytes` but returned as a string."""
        return binascii.hexlify(self.token_bytes(length)).decode("ascii")
