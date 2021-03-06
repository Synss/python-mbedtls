# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

# cython: c_api_binop_methods=True

"""Multi-precision integer library (MPI)."""


cimport mbedtls.mpi as _mpi
cimport mbedtls._random as _rnd
from libc.stdlib cimport malloc, free

import math
import numbers
from binascii import hexlify, unhexlify

import mbedtls.exceptions as _exc
import mbedtls._platform as _plt
import mbedtls._random as _rnd

try:
    long
except NameError:
    long = int


cdef _rnd.Random __rng = _rnd.default_rng()


cdef to_bytes(value):
    xx = "{0:02x}".format(value)
    return unhexlify((xx if not len(xx) % 2 else "0" + xx).encode("ascii"))


cdef from_bytes(value):
    return long(hexlify(value), 16)


cdef from_mpi_p(_mpi.mbedtls_mpi *mpi_p):
    cdef _mpi.MPI new_mpi = _mpi.MPI()
    _mpi.mbedtls_mpi_copy(&new_mpi._ctx, mpi_p)
    return new_mpi


cdef class MPI:
    """Multi-precision integer.

    This class implements `numbers.Integral`.  The representation
    of the MPI is overwritten with random bytes when the MPI is
    garbage collected.

    """
    def __init__(self, value=0):
        if isinstance(value, MPI):
            value_ = <MPI> value
            _exc.check_error(mbedtls_mpi_copy(&self._ctx, &value_._ctx))
        else:
            value = to_bytes(value)
            self._read_bytes(value)

    def __cinit__(self):
        """Initialize one MPI."""
        _mpi.mbedtls_mpi_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate one MPI."""
        _exc.check_error(mbedtls_mpi_fill_random(
            &self._ctx, self._len(),
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
        _mpi.mbedtls_mpi_free(&self._ctx)

    def __reduce__(self):
        byteorder = "big"
        return type(self).from_bytes, (
            self.to_bytes(self._len(), byteorder),
            byteorder,
        )

    cdef size_t _len(self):
        """Return the total size in bytes."""
        return _mpi.mbedtls_mpi_size(&self._ctx)

    def _read_bytes(self, const unsigned char[:] data not None):
        if data.size == 0:
            return MPI(0)
        _exc.check_error(
            _mpi.mbedtls_mpi_read_binary(&self._ctx, &data[0], data.shape[0]))

    def __str__(self):
        return "%i" % long(self)

    def __repr__(self):
        return "%s(%i)" % (type(self).__name__, long(self))

    def bit_length(self):
        """Return the number of bits necessary to represent MPI in binary."""
        return _mpi.mbedtls_mpi_bitlen(&self._ctx)

    @classmethod
    def from_int(cls, value):
        # mbedtls_mpi_lset is 'limited' to 64 bits.
        return cls.from_bytes(to_bytes(value), byteorder="big")

    @classmethod
    def from_bytes(cls, const unsigned char[:] data, byteorder):
        assert byteorder in {"big", "little"}
        self = cls()
        self._read_bytes(data[::-1 if byteorder == "little" else 1])
        return self

    def to_bytes(self, const size_t length, byteorder):
        assert byteorder in {"big", "little"}
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_mpi.mbedtls_mpi_write_binary(
                &self._ctx, output, length))
            return output[:length][::-1 if byteorder == "little" else 1]
        except Exception as exc:
            raise OverflowError from exc
        finally:
            free(output)

    __bytes__ = to_bytes

    @classmethod
    def prime(cls, size):
        """Return an MPI that is probably prime."""
        cdef MPI self_ = cls()
        _exc.check_error(mbedtls_mpi_gen_prime(
            &self_._ctx, size, 0,
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
        return self_

    def is_prime(self):
        """Miller-Rabin primality test."""
        return _exc.check_error(mbedtls_mpi_is_prime(
            &self._ctx,
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx)) == 0

    def __hash__(self):
        return long(self)

    def __bool__(self):
        return self != 0

    def __add__(self, other):
        if not all((isinstance(self, numbers.Integral),
                    isinstance(other, numbers.Integral))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        _exc.check_error(mbedtls_mpi_add_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __neg__(self):
        raise TypeError("negative value")

    def __pos__(self):
        return self

    def __sub__(self, other):
        if not all((isinstance(self, numbers.Integral),
                    isinstance(other, numbers.Integral))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        _exc.check_error(mbedtls_mpi_sub_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __mul__(self, other):
        if not all((isinstance(self, numbers.Integral),
                    isinstance(other, numbers.Integral))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        _exc.check_error(mbedtls_mpi_mul_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __truediv__(self, other):
        return NotImplemented

    def __pow__(MPI self, exponent, modulus):
        if not isinstance(exponent, numbers.Integral):
            return TypeError("exponent should be an integer")
        if not isinstance(modulus, numbers.Integral):
            return TypeError("modulus should be an integer")
        if exponent < 0:
            raise ValueError("exponent must be greater than zero")
        cdef MPI result = MPI()
        cdef MPI exponent_ = MPI(exponent)
        cdef MPI modulus_ = MPI(modulus)
        _exc.check_error(
            mbedtls_mpi_exp_mod(
                &result._ctx, &self._ctx, &exponent_._ctx, &modulus_._ctx, NULL
            )
        )
        return result

    def __abs__(self):
        # Negative values are not supported.
        return self

    def __eq__(MPI self, other):
        if not isinstance(other, numbers.Integral):
            return NotImplemented
        cdef MPI other_ = MPI(other)
        return mbedtls_mpi_cmp_mpi(&self._ctx, &other_._ctx) == 0

    def __float__(self):
        return float(long(self))

    def __trunc__(self):
        return self

    def __floor__(self):
        return self

    def __ceil__(self):
        return self

    def __round__(self, ndigits=None):
        return self

    def __divmod__(self, other):
        if not all((isinstance(self, numbers.Integral),
                    isinstance(other, numbers.Integral))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI quotient = MPI()
        cdef MPI rest = MPI()
        _exc.check_error(mbedtls_mpi_div_mpi(
            &quotient._ctx, &rest._ctx, &self_._ctx, &other_._ctx))
        return quotient, rest

    def __floordiv__(self, other):
        return divmod(self, other)[0]

    def __mod__(self, other):
        if not all((isinstance(self, numbers.Integral),
                    isinstance(other, numbers.Integral))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        _exc.check_error(mbedtls_mpi_mod_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __lt__(MPI self, other):
        if not isinstance(other, numbers.Integral):
            return NotImplemented
        cdef MPI other_ = MPI(other)
        return mbedtls_mpi_cmp_mpi(&self._ctx, &other_._ctx) == -1

    def __le__(MPI self, other):
        return self < other or self == other

    def __gt__(MPI self, other):
        return not self <= other

    def __ge__(MPI self, other):
        return self > other or self == other

    def __complex__(self):
        return complex(float(self))

    def real(self):
        return self

    def imag(self):
        return 0

    def conjugate(self):
        return self

    def __int__(self):
        n = self._len()
        if n:
            return from_bytes(self.to_bytes(n, byteorder="big"))
        else:
            return 0

    def __index__(self):
        return long(self)

    def __lshift__(MPI self, other):
        _exc.check_error(mbedtls_mpi_shift_l(&self._ctx, long(other)))
        return self

    def __rshift__(MPI self, other):
        _exc.check_error(mbedtls_mpi_shift_r(&self._ctx, long(other)))
        return self

    def __and__(MPI self, other):
        if not isinstance(other, MPI):
            other = MPI(other)
        cdef size_t size = long(
            math.ceil(max(self.bit_length(), other.bit_length()) / 8)
        )
        self_bin = bytearray(self.to_bytes(size, "big"))
        other_bin = bytearray(other.to_bytes(size, "big"))
        output = bytearray(size)
        cdef size_t ii
        for ii in range(size):
            output[ii] = self_bin[ii] & other_bin[ii]
        result = MPI.from_bytes(output, "big")
        _plt.zeroize(self_bin)
        _plt.zeroize(other_bin)
        _plt.zeroize(output)
        return result

    def __xor__(MPI self, other):
        if not isinstance(other, MPI):
            other = MPI(other)
        cdef size_t size = long(
            math.ceil(max(self.bit_length(), other.bit_length()) / 8)
        )
        self_bin = bytearray(self.to_bytes(size, "big"))
        other_bin = bytearray(other.to_bytes(size, "big"))
        output = bytearray(size)
        cdef size_t ii
        for ii in range(size):
            output[ii] = self_bin[ii] ^ other_bin[ii]
        result = MPI.from_bytes(output, "big")
        _plt.zeroize(self_bin)
        _plt.zeroize(other_bin)
        _plt.zeroize(output)
        return result

    def __or__(MPI self, other):
        if not isinstance(other, MPI):
            other = MPI(other)
        cdef size_t size = long(
            math.ceil(max(self.bit_length(), other.bit_length()) / 8)
        )
        self_bin = bytearray(self.to_bytes(size, "big"))
        other_bin = bytearray(other.to_bytes(size, "big"))
        output = bytearray(size)
        cdef size_t ii
        for ii in range(size):
            output[ii] = self_bin[ii] | other_bin[ii]
        result = MPI.from_bytes(output, "big")
        _plt.zeroize(self_bin)
        _plt.zeroize(other_bin)
        _plt.zeroize(output)
        return result

    def __invert__(self):
        raise TypeError("negative value")

    @property
    def numerator(self):
        return self

    @property
    def denominator(self):
        return 1


numbers.Integral.register(MPI)
