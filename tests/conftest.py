import random

import pytest


def _compare_memoryviews(_config, op, left, right):
    def _repr(obj):
        if isinstance(obj, memoryview):
            return "%s(%s)" % (type(obj).__name__, repr(obj.tobytes()))
        else:
            return repr(obj)

    try:
        _, _ = bytes(left), bytes(right)
    except TypeError:
        return [
            "%s != %s" % (_repr(left), _repr(right)),
            "-%s" % _repr(left),
            "+%s" % _repr(right),
        ]

    dlen = len(right) - len(left)
    if dlen > 0:
        return [
            "%s != %s" % (_repr(left), _repr(right)),
            "Right contains %s more items" % dlen,
        ]
    elif dlen < 0:
        return [
            "%s != %s" % (_repr(left), _repr(right)),
            "Left contains %d more items" % abs(dlen),
        ]
    else:
        return ["%s != %s" % (_repr(left), _repr(right))]


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
