import numbers
from binascii import hexlify, unhexlify

import pytest

from mbedtls.mpi import MPI


@pytest.mark.parametrize("value", (12, 2 ** 32 - 1, 10 ** 100))
def test_from_int(value):
    mpi = MPI.from_int(value)
    assert mpi == value
    assert value == mpi
    assert mpi == mpi


def test_is_integral():
    assert isinstance(MPI(42), numbers.Integral)


def test_prime():
    assert MPI.prime(512).is_prime()


def test_add():
    assert MPI(12) + MPI(12) == 24
    assert MPI(12) + 12 == 24
    assert 12 + MPI(12) == 24


def test_sub():
    assert MPI(12) - MPI(5) == 7
    assert MPI(12) - 5 == 7
    assert 12 - MPI(5) == 7


def test_mul():
    assert MPI(12) * MPI(2) == 24
    assert MPI(12) * 2 == 24
    assert 12 * MPI(2) == 24


def test_pow():
    assert MPI(12).__pow__(5, 12 ** 5 + 1) == 248832
    assert pow(MPI(12), 5, 12 ** 5 + 1) == 248832
    assert MPI(12).__pow__(5, 7) == 3
    assert pow(MPI(12), 5, 7) == 3


def test_eq_same_number_is_true():
    assert (MPI(12) == MPI(12)) is True
    assert (MPI(12) == 12) is True
    assert (12 == MPI(12)) is True


def test_eq_different_numbers_is_false():
    assert (MPI(12) == MPI(42)) is False
    assert (MPI(12) == 42) is False
    assert (12 == MPI(42)) is False


def test_neq_same_numbers_is_false():
    assert (MPI(12) != MPI(12)) is False
    assert (MPI(12) != 12) is False
    assert (12 != MPI(12)) is False


def test_neq_different_numbers_is_true():
    assert (MPI(12) != MPI(42)) is True
    assert (MPI(12) != 42) is True
    assert (12 != MPI(42)) is True


def test_lt_larger_number_is_true():
    assert (MPI(12) < MPI(42)) is True
    assert (MPI(12) < 42) is True
    assert (12 < MPI(42)) is True


def test_lt_smaller_number_is_false():
    assert (MPI(42) < MPI(12)) is False
    assert (MPI(42) < 12) is False
    assert (42 < MPI(12)) is False


def test_lt_same_number_is_false():
    assert (MPI(12) < MPI(12)) is False
    assert (MPI(12) < 12) is False
    assert (12 < MPI(12)) is False


def test_gt_larger_number_is_false():
    assert (MPI(12) > MPI(42)) is False
    assert (MPI(12) > 42) is False
    assert (12 > MPI(42)) is False


def test_gt_smaller_number_is_true():
    assert (MPI(42) > MPI(12)) is True
    assert (MPI(42) > 12) is True
    assert (42 > MPI(12)) is True


def test_gt_same_number_is_false():
    assert (MPI(12) > MPI(12)) is False
    assert (MPI(12) > 12) is False
    assert (12 > MPI(12)) is False


def test_le():
    assert (MPI(12) <= MPI(42)) is True
    assert (MPI(12) <= MPI(12)) is True
    assert (MPI(42) <= MPI(12)) is False


def test_ge():
    assert (MPI(42) >= MPI(12)) is True
    assert (MPI(42) >= MPI(42)) is True
    assert (MPI(12) >= MPI(42)) is False


def test_bool():
    assert bool(MPI(0)) is False


def test_float():
    assert float(MPI(12)) == 12.0


def test_rshift():
    assert MPI(12) >> MPI(2) == 3
    assert MPI(12) >> 2 == 3
    with pytest.raises(TypeError):
        assert 12 >> MPI(2) == 3


def test_lshift():
    assert MPI(12) << MPI(2) == 48
    assert MPI(12) << 2 == 48
    with pytest.raises(TypeError):
        assert 12 << MPI(2) == 48


def test_and():
    assert MPI(12) & MPI(12) == 12
    assert MPI(12) & MPI(3) == 0
    assert MPI(15) & MPI(4) == 4
    assert MPI(15) & 4 == 4
    with pytest.raises(TypeError):
        assert 15 & MPI(4) == 4


def test_or():
    assert MPI(12) | MPI(12) == 12
    assert MPI(12) | MPI(3) == 15
    assert MPI(15) | MPI(4) == 15
    assert MPI(15) | 4 == 15
    with pytest.raises(TypeError):
        assert 15 | MPI(4) == 15


def test_xor():
    assert MPI(12) ^ MPI(12) == 0
    assert MPI(12) ^ MPI(3) == 15
    assert MPI(15) ^ MPI(4) == 11
    assert MPI(15) ^ 4 == 11
    with pytest.raises(TypeError):
        assert 15 ^ MPI(4) == 11


def test_floordiv():
    assert MPI(24) // MPI(2) == 12
    assert MPI(24) // 2 == 12
    assert 24 // MPI(2) == 12


def test_mod():
    assert MPI(12) % MPI(10) == 2
    assert MPI(12) % 10 == 2
    assert 12 % MPI(10) == 2


@pytest.mark.parametrize("value", (12, 2 ** 32 - 1, 10 ** 100))
def test_bit_length(value):
    mpi = MPI(value)
    assert mpi == value
    assert mpi.bit_length() == value.bit_length()


def test_from_empty_bytes():
    value = b""
    big = MPI.from_bytes(value, byteorder="big")
    little = MPI.from_bytes(value, byteorder="little")
    assert big == little == 0
    assert big.bit_length() == little.bit_length() == 0


def test_from_bytes():
    value = unhexlify(b"DEADBEEF")
    mpi = MPI.from_bytes(value, byteorder="big")
    assert mpi.to_bytes(4, byteorder="big") == unhexlify(b"DEADBEEF")
    assert mpi.to_bytes(4, byteorder="little") == unhexlify(b"EFBEADDE")
    assert mpi == int(hexlify(value), 16)


def test_to_bytes_overflow():
    value = unhexlify(b"DEEADBEEFF")
    mpi = MPI.from_bytes(value, byteorder="big")
    with pytest.raises(OverflowError):
        mpi.to_bytes(2, byteorder="big")
