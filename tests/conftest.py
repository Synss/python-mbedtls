try:
    from collections.abc import Sequence
except ImportError:
    from collections import Sequence
try:
    import reprlib
except ImportError:
    import repr as reprlib
import random

import pytest


class _Repr(reprlib.Repr):
    """Repr with support for memoryview."""

    def repr_memoryview(self, obj, level):
        return "%s(%s)" % (type(obj).__name__, self.repr(obj.tobytes()))


_repr_instance = _Repr()
_repr = _repr_instance.repr


def issequence(x):
    # Adapted from pytest.
    if bytes != str:
        return isinstance(x, Sequence) and not isinstance(x, str)
    else:
        return isinstance(x, Sequence)


def _compare_memoryviews(_config, op, left, right):
    # Adapted from pytest.
    summary = ["{} != {}".format(_repr(left), _repr(right))]
    explanation = []
    if issequence(left) and issequence(right):
        for i in range(min(len(left), len(right))):
            if left[i] != right[i]:
                left_value = left[i : i + 1]
                right_value = right[i : i + 1]
                explanation += [
                    "At index {} diff: {} != {}".format(
                        i, _repr(left_value), _repr(right_value)
                    )
                ]
                break
    return summary + explanation


def pytest_assertrepr_compare(config, op, left, right):
    if op == "==" and any(
        (isinstance(left, memoryview), isinstance(right, memoryview))
    ):
        return _compare_memoryviews(config, op, left, right)
    return None


@pytest.fixture
def randbytes():
    def function(length):
        return bytes(
            bytearray(random.randrange(0, 256) for _ in range(length))
        )

    return function


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)
