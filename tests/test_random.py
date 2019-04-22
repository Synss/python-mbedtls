"""Unit tests for mbedtls.random."""

import random
from collections import defaultdict

import pytest

import mbedtls._random as _drbg
from mbedtls.exceptions import TLSError


def sample(start, end, k=20):
    return random.sample(range(start, end), k)


class TestEntropy:
    @pytest.fixture
    def entropy(self):
        return _drbg.Entropy()

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

    def test_random_initial_value(self, entropy):
        size = 4
        number = entropy.retrieve(size)
        result = defaultdict(int)
        for _ in range(250):
            result[_drbg.Entropy().retrieve(size) == number] += 1
        assert result[True] <= 1

    def test_random_retrieve(self, entropy):
        size = 4
        number = entropy.retrieve(size)
        result = defaultdict(int)
        for _ in range(250):
            result[entropy.retrieve(size) == number] += 1
        assert result[True] <= 1


class TestRandom:
    @pytest.fixture
    def entropy(self):
        return _drbg.Entropy()

    @pytest.fixture
    def random(self, entropy):
        return _drbg.Random(entropy)

    def test_reseed(self, random):
        random.reseed()

    def test_not_reproducible(self, random):
        assert random.token_bytes(8) != random.token_bytes(8)

    def test_update(self, random):
        random.update(b"additional data")

    def test_initial_values(self, random):
        other = _drbg.Random()
        assert random.token_bytes(8) != other.token_bytes(8)

    @pytest.mark.parametrize("length", range(1024))
    def test_token_bytes(self, random, length):
        assert len(random.token_bytes(length)) == length

    @pytest.mark.parametrize("length", range(1024))
    def test_token_hex(self, random, length):
        assert len(random.token_hex(length)) == 2 * length
