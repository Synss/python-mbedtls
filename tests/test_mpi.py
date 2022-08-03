# SPDX-License-Identifier: MIT

from __future__ import annotations

import math
import numbers
import pickle
from binascii import hexlify, unhexlify
from typing import Callable

import pytest

from mbedtls.mpi import MPI


@pytest.mark.parametrize("value", [12, 2**32 - 1, 10**100])
def test_from_int(value: int) -> None:
    mpi = MPI.from_int(value)
    assert mpi == value
    assert value == mpi
    assert mpi == mpi


@pytest.mark.parametrize(
    "repr_",
    [repr, str],
    ids=lambda f: f.__name__,  # type: ignore[no-any-return]
)
def test_repr(repr_: Callable[[object], str]) -> None:
    assert isinstance(repr_(MPI(69)), str)


def test_pickle() -> None:
    value = MPI(1337)
    assert value == pickle.loads(pickle.dumps(value))


def test_hash() -> None:
    assert isinstance(hash(MPI(1337)), int)


def test_is_integral() -> None:
    assert isinstance(MPI(42), numbers.Integral)


def test_add() -> None:
    assert MPI(12) + MPI(12) == 24
    assert isinstance(MPI(12) + MPI(12), MPI)

    assert MPI(12) + 12 == 24
    assert isinstance(MPI(12) + 12, MPI)

    assert 12 + MPI(12) == 24
    assert isinstance(12 + MPI(12), MPI)


def test_sub() -> None:
    assert MPI(12) - MPI(5) == 7
    assert isinstance(MPI(12) - MPI(5), MPI)

    assert MPI(12) - 5 == 7
    assert isinstance(MPI(12) - 5, MPI)

    assert 12 - MPI(5) == 7
    assert isinstance(12 - MPI(5), MPI)


def test_mul() -> None:
    assert MPI(12) * MPI(2) == 24
    assert isinstance(MPI(12) * MPI(2), MPI)

    assert MPI(12) * 2 == 24
    assert isinstance(MPI(12) * 2, MPI)

    assert 12 * MPI(2) == 24
    assert isinstance(12 * MPI(2), MPI)


def test_pow() -> None:
    assert MPI(12).__pow__(5, 12**5 + 1) == 248832
    assert isinstance(MPI(12).__pow__(5, 12**5 + 1), MPI)

    assert pow(MPI(12), 5, 12**5 + 1) == 248832
    assert isinstance(pow(MPI(12), 5, 12**5 + 1), MPI)

    assert MPI(12).__pow__(5, 7) == 3
    assert isinstance(MPI(12).__pow__(5, 7), MPI)

    assert pow(MPI(12), 5, 7) == 3
    assert isinstance(pow(MPI(12), 5, 7), MPI)


def test_eq() -> None:
    assert MPI(12) == MPI(12)
    assert MPI(12) == 12
    assert 12 == MPI(12)


def test_eq_no_implicit_conversion() -> None:
    assert MPI(12) != 12.0
    assert 12.0 != MPI(12)


def test_neq() -> None:
    assert MPI(12) != MPI(42)
    assert MPI(12) != 42
    assert 12 != MPI(42)
    assert MPI(12) != 42.0
    assert 12.0 != MPI(42)


def test_lt() -> None:
    assert MPI(12) < MPI(42)
    assert MPI(12) < 42
    assert 12 < MPI(42)

    assert not MPI(42) < MPI(12)
    assert not MPI(42) < 12
    assert not 42 < MPI(12)

    assert not MPI(12) < MPI(12)
    assert not MPI(12) < 12
    assert not 12 < MPI(12)


def test_lt_no_implicit_converstions() -> None:
    with pytest.raises(TypeError):
        assert MPI(12) < 42.0  # type: ignore[operator]

    with pytest.raises(TypeError):
        assert 12.0 < MPI(42)  # type: ignore[operator]


def test_gt_larger_number_is_false() -> None:
    assert (MPI(12) > MPI(42)) is False
    assert (MPI(12) > 42) is False
    assert (12 > MPI(42)) is False


def test_gt_smaller_number_is_true() -> None:
    assert (MPI(42) > MPI(12)) is True
    assert (MPI(42) > 12) is True
    assert (42 > MPI(12)) is True


def test_gt_same_number_is_false() -> None:
    assert (MPI(12) > MPI(12)) is False
    assert (MPI(12) > 12) is False
    assert (12 > MPI(12)) is False


def test_le() -> None:
    assert (MPI(12) <= MPI(42)) is True
    assert (MPI(12) <= MPI(12)) is True
    assert (MPI(42) <= MPI(12)) is False


def test_ge() -> None:
    assert (MPI(42) >= MPI(12)) is True
    assert (MPI(42) >= MPI(42)) is True
    assert (MPI(12) >= MPI(42)) is False


def test_bool() -> None:
    assert bool(MPI(0)) is False


def test_float() -> None:
    assert isinstance(float(MPI(12)), float)
    assert not isinstance(float(MPI(12)), numbers.Integral)
    assert isinstance(float(MPI(12)), numbers.Real)
    assert float(MPI(12)) == 12.0


def test_trunc() -> None:
    assert isinstance(math.trunc(MPI(12)), numbers.Integral)
    assert math.trunc(MPI(12)) == 12


def test_floor() -> None:
    assert isinstance(math.floor(MPI(12)), numbers.Integral)
    assert math.floor(MPI(12)) == 12


def test_ceil() -> None:
    assert isinstance(math.ceil(MPI(12)), numbers.Integral)
    assert math.ceil(MPI(12)) == 12


def test_round() -> None:
    assert isinstance(round(MPI(12)), numbers.Integral)
    assert round(MPI(12)) == 12
    assert round(MPI(12), 0) == 12


def test_rshift() -> None:
    assert MPI(12) >> MPI(2) == 3
    assert isinstance(MPI(12) >> MPI(2), MPI)

    assert MPI(12) >> 2 == 3
    assert isinstance(MPI(12) >> 2, MPI)

    with pytest.raises(TypeError):
        assert 12 >> MPI(2) == 3


def test_lshift() -> None:
    assert MPI(12) << MPI(2) == 48
    assert isinstance(MPI(12) << MPI(2), MPI)

    assert MPI(12) << 2 == 48
    assert isinstance(MPI(12) << 2, MPI)

    with pytest.raises(TypeError):
        assert 12 << MPI(2) == 48


def test_and() -> None:
    assert MPI(12) & MPI(12) == 12
    assert isinstance(MPI(12) & MPI(12), MPI)

    assert MPI(12) & MPI(3) == 0
    assert isinstance(MPI(12) & MPI(3), MPI)

    assert MPI(15) & MPI(4) == 4
    assert isinstance(MPI(15) & MPI(4), MPI)

    assert MPI(15) & 4 == 4
    assert isinstance(MPI(15) & 4, MPI)

    with pytest.raises(TypeError):
        assert 15 & MPI(4) == 4


def test_or() -> None:
    assert MPI(12) | MPI(12) == 12
    assert isinstance(MPI(12) | MPI(12), MPI)

    assert MPI(12) | MPI(3) == 15
    assert isinstance(MPI(12) | MPI(3), MPI)

    assert MPI(15) | MPI(4) == 15
    assert isinstance(MPI(15) | MPI(4), MPI)

    assert MPI(15) | 4 == 15
    assert isinstance(MPI(15) | 4, MPI)

    with pytest.raises(TypeError):
        assert 15 | MPI(4) == 15


def test_xor() -> None:
    assert MPI(12) ^ MPI(12) == 0
    assert isinstance(MPI(12) ^ MPI(12), MPI)

    assert MPI(12) ^ MPI(3) == 15
    assert isinstance(MPI(12) ^ MPI(3), MPI)

    assert MPI(15) ^ MPI(4) == 11
    assert isinstance(MPI(15) ^ MPI(4), MPI)

    assert MPI(15) ^ 4 == 11
    assert isinstance(MPI(15) ^ 4, MPI)

    with pytest.raises(TypeError):
        assert 15 ^ MPI(4) == 11


def test_floordiv() -> None:
    assert MPI(24) // MPI(2) == 12
    assert isinstance(MPI(24) // MPI(2), MPI)

    assert MPI(24) // 2 == 12
    assert isinstance(MPI(24) // 2, MPI)

    assert 24 // MPI(2) == 12
    assert isinstance(24 // MPI(2), MPI)


def test_mod() -> None:
    assert MPI(12) % MPI(10) == 2
    assert isinstance(MPI(12) % MPI(10), MPI)

    assert MPI(12) % 10 == 2
    assert isinstance(MPI(12) % 10, MPI)

    assert 12 % MPI(10) == 2
    assert isinstance(12 % MPI(10), MPI)


@pytest.mark.parametrize("value", [12, 2**32 - 1, 10**100])
def test_bit_length(value: int) -> None:
    mpi = MPI(value)
    assert mpi == value
    assert mpi.bit_length() == value.bit_length()


def test_from_empty_bytes() -> None:
    value = b""
    big = MPI.from_bytes(value, byteorder="big")
    little = MPI.from_bytes(value, byteorder="little")
    assert big == little == 0
    assert big.bit_length() == little.bit_length() == 0


def test_from_bytes() -> None:
    value = unhexlify(b"DEADBEEF")
    mpi = MPI.from_bytes(value, byteorder="big")
    assert mpi.to_bytes(4, byteorder="big") == unhexlify(b"DEADBEEF")
    assert mpi.to_bytes(4, byteorder="little") == unhexlify(b"EFBEADDE")
    assert mpi == int(hexlify(value), 16)


def test_to_bytes_overflow() -> None:
    value = unhexlify(b"DEEADBEEFF")
    mpi = MPI.from_bytes(value, byteorder="big")
    with pytest.raises(OverflowError):
        mpi.to_bytes(2, byteorder="big")
