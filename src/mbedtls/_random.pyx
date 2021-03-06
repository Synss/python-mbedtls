# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Random number generator (RNG) wrapper."""


from libc.stdlib cimport malloc, free

cimport mbedtls._platform as _plt
cimport mbedtls._random as _rnd

import numbers as _numbers

import mbedtls.mpi as _mpi
from mbedtls.exceptions import check_error


BPF = 53  # Number of bits in a float
RECIP_BPF = 2**-BPF


cdef class _Entropy:
    def __cinit__(self):
        """Initialize the context."""
        _rnd.mbedtls_entropy_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _rnd.mbedtls_entropy_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def gather(self):
        """Trigger an extra gather poll for the accumulator."""
        _rnd.mbedtls_entropy_gather(&self._ctx)

    def retrieve(self, size_t length):
        """Retrieve entropy from the accumulator."""
        cdef unsigned char *output = <unsigned char *> malloc(
            length * sizeof(unsigned char)
        )
        if not output:
            raise MemoryError()
        try:
            check_error(_rnd.mbedtls_entropy_func(&self._ctx, output, length))
            return output[:length]
        finally:
            free(output)

    def update(self, const unsigned char[:] data):
        """Add data to the accumulator manually."""
        check_error(
            _rnd.mbedtls_entropy_update_manual(
                &self._ctx, &data[0], data.shape[0]
            )
        )


cdef class Random:
    def __init__(self):
        self._entropy = _Entropy()
        check_error(
            _rnd.mbedtls_ctr_drbg_seed(
                &self._ctx,
                &_rnd.mbedtls_entropy_func,
                &self._entropy._ctx,
                NULL, 0
            )
        )

    def __cinit__(self):
        """Initialize the context."""
        _rnd.mbedtls_ctr_drbg_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _rnd.mbedtls_ctr_drbg_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    @property
    def _entropy(self):
        return self._entropy

    def _reseed(self, const unsigned char[:] data=None):
        """Reseed the RNG."""
        if data is None:
            check_error(_rnd.mbedtls_ctr_drbg_reseed(&self._ctx, NULL, 0))
        else:
            check_error(
                _rnd.mbedtls_ctr_drbg_reseed(&self._ctx, &data[0], data.size)
            )

    def urandom(self, size_t length):
        """Returns `length` random bytes."""
        cdef unsigned char *output = <unsigned char *> malloc(
            length * sizeof(unsigned char)
        )
        if not output:
            raise MemoryError()
        try:
            check_error(
                _rnd.mbedtls_ctr_drbg_random(&self._ctx, output, length)
            )
            ret = output[:length]
            _plt.mbedtls_platform_zeroize(output, length)
            return ret
        finally:
            free(output)

    def randbelow(self, upper_bound):
        """Return a random int in the range [0, n).

        Raises ValueError if n <= 0.

        """
        if upper_bound <= 0:
            raise ValueError("Upper bound must be positive.")
        kk = upper_bound.bit_length()
        rr = self.getrandbits(kk)
        while rr >= upper_bound:
            rr = self.getrandbits(kk)
        return rr

    def random(self):
        """Return the next random floating point number."""
        # Algorithm taken from Python's secrets and random libraries.
        return float(
            _mpi.MPI.from_bytes(self.urandom(7), "big") >> 3
        ) * RECIP_BPF

    def getrandbits(self, k):
        """Generate an int with `k` random bits."""
        # Algorithm adapted from Python's secrets and random libraries.
        if k <= 0:
            raise ValueError("number of bits must be greater than zero")
        if not isinstance(k, _numbers.Integral):
            raise TypeError("number of bits should be an integer")
        numbytes = (k + 7) // 8
        value = _mpi.MPI.from_bytes(self.urandom(numbytes), "big")
        # Trim excess bits:
        extra_bits = value.bit_length() - k
        return value >> (0 if extra_bits <= 0 else extra_bits)

    def choice(self, seq):
        """Return a random element from `seq`."""
        try:
            ii = self.randbelow(len(seq))
        except ValueError:
            raise IndexError("Cannot choose from an empty sequence")
        return seq[ii]


cdef Random __rng = Random()


cpdef Random default_rng():
    return __rng
