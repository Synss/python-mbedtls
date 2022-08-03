# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest


@pytest.mark.xfail(reason="Test assertion rewriting")
class TestMemoryviewAssertion:
    @pytest.fixture()
    def value(self) -> bytes:
        return bytes(_ % 256 for _ in range(10000))

    def test_memview_and_memview(self, value: bytes) -> None:
        view = memoryview(value)
        assert view == view[::-1]

    def test_bytes_and_shorter_memview(self, value: bytes) -> None:
        view = memoryview(value)
        assert value == view[:-1]

    def test_shorter_memview_and_bytes(self, value: bytes) -> None:
        view = memoryview(value)
        assert view[:-1] == value

    def test_bytes_and_longer_memview(self, value: bytes) -> None:
        view = memoryview(value)
        assert value[:-1] == view

    def test_longer_memview_and_bytes(self, value: bytes) -> None:
        view = memoryview(value)
        assert view == value[:-1]

    def test_memview_and_str(self, value: bytes) -> None:
        text = value.decode("latin1")
        view = memoryview(value)
        assert view == text  # type: ignore[comparison-overlap]

    def test_str_and_memview(self, value: bytes) -> None:
        text = value.decode("latin1")
        view = memoryview(value)
        assert text == view  # type: ignore[comparison-overlap]
