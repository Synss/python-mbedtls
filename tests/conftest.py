import pytest
import random


@pytest.fixture
def randbytes():
    def function(length):
        return bytes(bytearray(random.randrange(0, 256)
                               for _ in range(length)))
    return function
