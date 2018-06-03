"""Multi-precision integer library (MPI)."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls._mpi as _mpi
from libc.stdlib cimport malloc, free

import numbers
from binascii import hexlify, unhexlify

from mbedtls.exceptions import *

try:
    long
except NameError:
    long = int


cdef to_bytes(value):
    return unhexlify("{0:02x}".format(value).encode("ascii"))


cdef from_bytes(value):
    return long(hexlify(value), 16)


cdef class MPI:
    """Multi-precision integer.

    Only minimal bindings here because Python already has
    arbitrary-precision integers.

    """
    def __init__(self, value=0):
        if isinstance(value, MPI):
            value_ = <MPI> value
            check_error(mbedtls_mpi_copy(&self._ctx, &value_._ctx))
        else:
            value = to_bytes(value)
            self._from_bytes(value)

    def __cinit__(self):
        """Initialize one MPI."""
        _mpi.mbedtls_mpi_init(&self._ctx)

    def __dealloc__(self):
        """Unallocate one MPI."""
        _mpi.mbedtls_mpi_free(&self._ctx)

    cdef _len(self):
        """Return the total size in bytes."""
        return _mpi.mbedtls_mpi_size(&self._ctx)

    cpdef _from_bytes(self, const unsigned char[:] bytes):
        check_error(
            _mpi.mbedtls_mpi_read_binary(&self._ctx, &bytes[0], bytes.shape[0]))
        return self

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

    def __eq__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        return mbedtls_mpi_cmp_mpi(&self_._ctx, &other_._ctx) == 0

    def __hash__(self):
        return long(self)

    def __int__(self):
        return from_bytes(self.to_bytes(self._len(), byteorder="big"))

    def __float__(self):
        return float(long(self))

    def __index__(self):
        return long(self)

    def __lshift__(self, other):
        if not isinstance(self, MPI):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        check_error(mbedtls_mpi_shift_l(&self_._ctx, long(other)))
        return self_

    def __rshift__(self, other):
        if not isinstance(self, MPI):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        check_error(mbedtls_mpi_shift_r(&self_._ctx, long(other)))
        return self_

    def __add__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        check_error(mbedtls_mpi_add_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __sub__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        check_error(mbedtls_mpi_sub_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __mul__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        check_error(mbedtls_mpi_mul_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    def __floordiv__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI quotient = MPI()
        cdef MPI rest = MPI()
        check_error(mbedtls_mpi_div_mpi(
            &quotient._ctx, &rest._ctx, &self_._ctx, &other_._ctx))
        return quotient

    def __mod__(self, other):
        if not all((isinstance(self, (MPI, numbers.Integral)),
                    isinstance(other, (MPI, numbers.Integral)))):
            return NotImplemented
        cdef MPI self_ = MPI(self)
        cdef MPI other_ = MPI(other)
        cdef MPI result = MPI()
        check_error(mbedtls_mpi_mod_mpi(
            &result._ctx, &self_._ctx, &other_._ctx))
        return result

    @classmethod
    def from_bytes(cls, bytes, byteorder):
        assert byteorder in {"big", "little"}
        order = slice(None, None, -1 if byteorder is "little" else None)
        return cls()._from_bytes(bytes[order])

    def to_bytes(self, length, byteorder):
        assert byteorder in {"big", "little"}
        order = slice(None, None, -1 if byteorder is "little" else None)
        cdef unsigned char* output = <unsigned char*>malloc(
            length * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_mpi.mbedtls_mpi_write_binary(
                &self._ctx, output, length))
            return bytes(output[:length])[order]
        except Exception as exc:
            raise OverflowError from exc
        finally:
            free(output)

    __bytes__ = to_bytes
