"""Unit tests for mbedtls.random."""
# pylint: disable=missing-docstring

# pylint: disable=import-error
import mbedtls.entropy as _entropy
# pylint: enable=import-error
from mbedtls.exceptions import EntropySourceError

from nose.tools import assert_equal, raises
from . import _rnd


def assert_length(collection, length):
    assert_equal(len(collection), length)
assert_length.__test__ = False


def test_entropy_instantiation():
    _entropy.Entropy()


def test_entropy_gather():
    entropy = _entropy.Entropy()
    entropy.gather()


def test_entropy_retrieve():
    entropy = _entropy.Entropy()
    for length in range(64):
        assert_length(entropy.retrieve(length), length)


@raises(EntropySourceError)
def test_retrieve_long_entropy_block_raises():
    entropy = _entropy.Entropy()
    entropy.retrieve(100)


def test_entropy_update():
    # Only test that this does not raise.
    entropy = _entropy.Entropy()
    buf = _rnd(64)
    entropy.update(buf)
