"""Unit tests for mbedtls.random."""
# pylint: disable=missing-docstring


# pylint: disable=import-error
import mbedtls.random as _drbg
# pylint: enable=import-error
from nose.tools import assert_equal, assert_not_equal


def assert_length(collection, length):
    assert_equal(len(collection), length)
assert_length.__test__ = False


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
