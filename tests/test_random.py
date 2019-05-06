"""Unit tests for mbedtls.random."""

import random
from collections import defaultdict

import pytest

import mbedtls.mpi as _mpi
import mbedtls._random as _drbg
from mbedtls.exceptions import TLSError


def sample(start, end, k=20):
    return random.sample(range(start, end), k)


class TestEntropy:
    @pytest.fixture
    def entropy(self):
        return _drbg.Random()._entropy

    def test_gather(self, entropy):
        # Only test that this does not raise.
        entropy.gather()

    @pytest.mark.parametrize("length", range(64))
    def test_retrieve(self, entropy, length):
        assert len(entropy.retrieve(length)) == length

    @pytest.mark.parametrize("length", (100,))
    def test_retrieve_long_block_raises_exception(self, entropy, length):
        with pytest.raises(TLSError):
            entropy.retrieve(length)

    def test_update(self, entropy, randbytes):
        # Only test that this does not raise.
        buf = randbytes(64)
        entropy.update(buf)

    def test_not_reproducible(self, entropy):
        assert entropy.retrieve(8) != entropy.retrieve(8)

    def test_random_retrieve(self, entropy):
        size = 4
        number = entropy.retrieve(size)
        result = defaultdict(int)
        for _ in range(250):
            result[entropy.retrieve(size) == number] += 1
        assert result[True] <= 1


class TestRandom:
    @pytest.fixture
    def random(self):
        return _drbg.Random()

    def test_reseed(self, random):
        random._reseed()

    @pytest.mark.repeat(10)
    @pytest.mark.parametrize("max", range(1, 300))
    def test_randbelow(self, random, max):
        assert 0 <= random._randbelow(max) < max

    def test_randbelow_zero_raises_valueerror(self, random):
        with pytest.raises(ValueError):
            random._randbelow(0)

    @pytest.mark.repeat(100)
    def test_random(self, random):
        value = random.random()
        assert isinstance(value, float)
        assert 0 <= value < 1

    @pytest.mark.repeat(100)
    def test_random_not_reproducible(self, random):
        assert random.random() != random.random()

    @pytest.mark.repeat(100)
    def test_getrandbits_not_reproducible(self, random):
        assert random.getrandbits(64) != random.getrandbits(64)

    @pytest.mark.repeat(100)
    def test_random_initial_values(self):
        random = _drbg.Random()
        other = _drbg.Random()
        assert random.random() != other.random()

    @pytest.mark.repeat(100)
    def test_getrandbits_initial_values(self):
        random = _drbg.Random()
        other = _drbg.Random()
        assert random.getrandbits(64) != other.getrandbits(64)

    @pytest.mark.parametrize("nbits", [1, 5, 10, 50, 100, 300, 500])
    def test_getrandbits_size(self, random, nbits):
        value = random.getrandbits(nbits)
        assert isinstance(value, _mpi.MPI)
        assert value.bit_length() == pytest.approx(nbits, abs=7)
        assert value.bit_length() <= nbits

    @pytest.mark.parametrize("nbits", [-1, 0])
    def test_getrandbits_negative_k_raises_value_error(self, random, nbits):
        with pytest.raises(ValueError):
            random.getrandbits(nbits)

    def test_getrandbits_nonint_k_raises_type_error(self, random):
        with pytest.raises(TypeError):
            random.getrandbits("a")
