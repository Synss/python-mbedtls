"""Random number generator (RNG) wrapper."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


from libc.stdlib cimport malloc, free
cimport entropy
cimport random
import binascii
from mbedtls.exceptions import check_error


cdef class Random:

    cdef mbedtls_ctr_drbg_context _ctx
    cdef entropy.Entropy _entropy

    def __cinit__(self):
        """Initialize the context."""
        random.mbedtls_ctr_drbg_init(&self._ctx)
        self._entropy = entropy.Entropy()
        check_error(random.mbedtls_ctr_drbg_seed(
            &self._ctx,
            &entropy.mbedtls_entropy_func, &self._entropy._ctx,
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
            return bytes([output[n] for n in range(sz)])
        finally:
            free(output)

    cpdef token_hex(self, length):
        """Same as `token_bytes` but returned as a string."""
        return binascii.hexlify(self.token_bytes(length)).decode("ascii")
