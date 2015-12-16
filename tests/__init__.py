import random


def assert_canonical_repr(obj):
    # ``eval`` *must* run into the caller's environment, so let's get it from
    # the stack.
    from inspect import stack
    frame = stack()[1][0]
    try:
        # pylint: disable=eval-used
        newobj = eval(repr(obj), frame.f_globals, frame.f_locals)
    except TypeError:
        raise AssertionError("Cannot eval '%r'" % obj) from None
    finally:
        # explicitely delete the frame to avoid memory leaks, see also
        # https://docs.python.org/3/library/inspect.html#the-interpreter-stack
        del frame
    assert isinstance(newobj, type(obj))
assert_canonical_repr.__test__ = False


def _rnd(length):
    return bytes(random.randrange(0, 256) for _ in range(length))
_rnd.__test__ = False


class TestRnd:

    @staticmethod
    def test_key_length():
        for length in range(1024 + 1, 8):
            assert len(_rnd(length)) == length

    @staticmethod
    def test_values_fit_in_latin1():
        k = _rnd(2048)
        assert k.decode("latin1")
