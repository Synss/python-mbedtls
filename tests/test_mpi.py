from binascii import hexlify, unhexlify

import pytest

from mbedtls._mpi import MPI


@pytest.mark.parametrize("value", (12, 2**32 - 1, 10**100))
def test_from_int(value):
    mpi = MPI.from_int(value)
    assert mpi == value


@pytest.mark.parametrize("value", (12, 2**32 - 1, 10**100))
def test_bit_length(value):
    mpi = MPI(value)
    assert mpi == value
    assert mpi.bit_length() == value.bit_length()


def test_from_bytes():
    value = unhexlify(b"DEEADBEEFF")
    mpi = MPI.from_bytes(value, byteorder="big")
    assert mpi.to_bytes(5, byteorder="big") == value
    assert mpi.to_bytes(5, byteorder="little") == value[::-1]
    assert mpi == int(hexlify(value), 16)


def test_to_bytes_overflow():
    value = unhexlify(b"DEEADBEEFF")
    mpi = MPI.from_bytes(value, byteorder="big")
    with pytest.raises(OverflowError):
        mpi.to_bytes(2, byteorder="big")
