"""Unit tests for mbedtls.random."""
# pylint: disable=missing-docstring


# pylint: disable=import-error
import mbedtls.random as _drbg
# pylint: enable=import-error
from nose.tools import assert_equal, assert_not_equal, raises
from mbedtls.exceptions import EntropyError
from . import _rnd


def assert_length(collection, length):
    assert_equal(len(collection), length)
assert_length.__test__ = False


class TestEntropy:

    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        # pylint: disable=invalid-name
        self.s = _drbg.Entropy()

    def test_gather(self):
        # Only test that this does not raise.
        self.s.gather()

    def test_retrieve(self):
        for length in range(64):
            assert_length(self.s.retrieve(length), length)

    @raises(EntropyError)
    def test_retrieve_long_block_raises(self):
        self.s.retrieve(100)

    def test_update(self):
        # Only test that this does not raise.
        buf = _rnd(64)
        self.s.update(buf)

    def test_not_reproducible(self):
        assert_not_equal(self.s.retrieve(8), self.s.retrieve(8))

    def test_random_initial_values(self):
        # pylint: disable=invalid-name
        s = _drbg.Entropy()
        assert_not_equal(self.s.retrieve(8), s.retrieve(8))


class TestRandom:

    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        self.rnd = _drbg.Random()

    def test_reseed(self):
        self.rnd.reseed()

    def test_not_reproducible(self):
        assert_not_equal(self.rnd.token_bytes(8),
                         self.rnd.token_bytes(8))

    def test_update(self):
        self.rnd.update(b"additional data")

    def test_initial_values(self):
        rnd = _drbg.Random()
        assert_not_equal(self.rnd.token_bytes(8),
                         rnd.token_bytes(8))

    def test_token_bytes(self):
        for length in range(1024):
            assert_length(self.rnd.token_bytes(length), length)

    def test_token_hex(self):
        for length in range(1024):
            assert_length(self.rnd.token_hex(length), 2 * length)
