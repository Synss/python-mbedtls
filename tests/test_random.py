# SPDX-License-Identifier: MIT

"""Unit tests for mbedtls.random."""

from __future__ import annotations

import pickle
import random
from collections import defaultdict
from typing import Callable, MutableMapping, Sequence

import pytest

import mbedtls._random as _drbg
import mbedtls.mpi as _mpi
from mbedtls.exceptions import TLSError


def sample(start: int, end: int, k: int = 20) -> Sequence[int]:
    return random.sample(range(start, end), k)


class TestEntropy:
    def test_pickle(self) -> None:
        entropy = _drbg.Random()._entropy
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(entropy)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_gather(self) -> None:
        # Only test that this does not raise.
        _drbg.Random()._entropy.gather()

    @pytest.mark.parametrize("length", range(64))
    def test_retrieve(self, length: int) -> None:
        entropy = _drbg.Random()._entropy
        assert len(entropy.retrieve(length)) == length

    @pytest.mark.parametrize("length", [100])
    def test_retrieve_long_block_raises_exception(self, length: int) -> None:
        entropy = _drbg.Random()._entropy
        with pytest.raises(TLSError):
            entropy.retrieve(length)

    def test_update(self, randbytes: Callable[[int], bytes]) -> None:
        # Only test that this does not raise.
        buf = randbytes(64)
        _drbg.Random()._entropy.update(buf)

    def test_not_reproducible(self) -> None:
        entropy = _drbg.Random()._entropy
        assert entropy.retrieve(8) != entropy.retrieve(8)

    def test_random_retrieve(self) -> None:
        size = 4
        entropy = _drbg.Random()._entropy
        number = entropy.retrieve(size)
        result: MutableMapping[bool, int] = defaultdict(int)
        for _ in range(250):
            result[entropy.retrieve(size) == number] += 1
        assert result[True] <= 1


class TestRandom:
    def test_pickle(self) -> None:
        random = _drbg.Random()
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(random)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_reseed(self) -> None:
        _drbg.Random()._reseed()

    @pytest.mark.repeat(100)
    def test_random(self) -> None:
        value = _drbg.Random().random()
        assert isinstance(value, float)
        assert 0 <= value < 1

    @pytest.mark.repeat(100)
    def test_random_not_reproducible(self) -> None:
        random = _drbg.Random()
        assert random.random() != random.random()

    @pytest.mark.repeat(100)
    def test_getrandbits_not_reproducible(self) -> None:
        random = _drbg.Random()
        assert random.getrandbits(64) != random.getrandbits(64)

    @pytest.mark.repeat(100)
    def test_random_initial_values(self) -> None:
        random = _drbg.Random()
        other = _drbg.Random()
        assert random.random() != other.random()

    @pytest.mark.repeat(100)
    def test_getrandbits_initial_values(self) -> None:
        random = _drbg.Random()
        other = _drbg.Random()
        assert random.getrandbits(64) != other.getrandbits(64)

    @pytest.mark.parametrize("nbits", [1, 5, 10, 50, 100, 300, 500])
    def test_getrandbits_size(self, nbits: int) -> None:
        random = _drbg.Random()
        value = random.getrandbits(nbits)
        assert isinstance(value, _mpi.MPI)
        assert value.bit_length() == pytest.approx(nbits, abs=8)
        assert value.bit_length() <= nbits

    @pytest.mark.parametrize("nbits", [-1, 0])
    def test_getrandbits_negative_k_raises_value_error(
        self, nbits: int
    ) -> None:
        random = _drbg.Random()
        with pytest.raises(ValueError):
            random.getrandbits(nbits)

    def test_getrandbits_nonint_k_raises_type_error(self) -> None:
        random = _drbg.Random()
        with pytest.raises(TypeError):
            random.getrandbits("a")  # type: ignore[arg-type]
