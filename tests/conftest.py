# SPDX-License-Identifier: MIT

from __future__ import annotations

import random
import reprlib
import sys
from typing import Callable, Optional, Sequence

import pytest

import mbedtls


def pytest_report_header(config: object, startdir: object) -> None:
    sys.stdout.write(
        "python-mbedtls {}, {}\n".format(
            mbedtls.__version__, mbedtls.version.version
        )
    )


class _Repr(reprlib.Repr):
    """Repr with support for memoryview."""

    def repr_memoryview(self, obj: memoryview, level: object) -> str:
        return f"{type(obj).__name__}({self.repr(obj.tobytes())})"


_repr_instance = _Repr()
_repr = _repr_instance.repr


def _compare_memoryviews(
    _config: object, op: object, left: object, right: object
) -> Sequence[str]:
    # Adapted from pytest.
    summary = [f"{_repr(left)} != {_repr(right)}"]
    explanation = []
    if isinstance(left, Sequence) and isinstance(right, Sequence):
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


def pytest_assertrepr_compare(
    config: object, op: object, left: object, right: object
) -> Optional[Sequence[str]]:
    if op == "==" and any(
        (isinstance(left, memoryview), isinstance(right, memoryview))
    ):
        return _compare_memoryviews(config, op, left, right)
    return None


@pytest.fixture()
def randbytes() -> Callable[[int], bytes]:
    def function(length: int) -> bytes:
        return bytes(
            bytearray(random.randrange(0, 256) for _ in range(length))
        )

    return function
