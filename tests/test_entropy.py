"""Unit tests for mbedtls.random."""
# pylint: disable=missing-docstring

# pylint: disable=import-error
import mbedtls.entropy as _entropy
# pylint: enable=import-error
from mbedtls.exceptions import EntropySourceError

from nose.tools import assert_equal, assert_not_equal, raises
from . import _rnd


def assert_length(collection, length):
    assert_equal(len(collection), length)
assert_length.__test__ = False


class TestEntropy:

    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        # pylint: disable=invalid-name
        self.s = _entropy.Entropy()

    def test_gather(self):
        # Only test that this does not raise.
        self.s.gather()

    def test_retrieve(self):
        for length in range(64):
            assert_length(self.s.retrieve(length), length)

    @raises(EntropySourceError)
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
        s = _entropy.Entropy()
        assert_not_equal(self.s.retrieve(8), s.retrieve(8))
