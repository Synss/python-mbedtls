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
    def __init__(self, value):
        if value is None:
            return  # Implementation detail.
        try:
            value = to_bytes(value)
        except TypeError:
            pass
        self._from_bytes(bytearray(value))

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

    def bit_length(self):
        """Return the number of bits necessary to represent MPI in binary."""
        return _mpi.mbedtls_mpi_bitlen(&self._ctx)

    def __eq__(self, other):
        if not isinstance(other, numbers.Integral):
            raise NotImplemented
        return long(self) == other

    @classmethod
    def from_int(cls, value):
        # mbedtls_mpi_lset is 'limited' to 64 bits.
        return cls.from_bytes(to_bytes(value), byteorder="big")

    def __int__(self):
        return from_bytes(self.to_bytes(self._len(), byteorder="big"))

    @classmethod
    def from_bytes(cls, bytes, byteorder):
        assert byteorder in {"big", "little"}
        order = slice(None, None, -1 if byteorder is "little" else None)
        return cls(None)._from_bytes(bytearray(bytes[order]))

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
