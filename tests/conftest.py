import pytest

import random


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
