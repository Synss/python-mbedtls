import pytest


@pytest.mark.xfail(reason="Test assertion rewriting")
class TestMemoryviewAssertion:
    @pytest.fixture
    def value(self):
        return b"a few random bytes"

    @pytest.fixture
    def text(self, value):
        return value.decode("ascii")

    @pytest.fixture
    def memview(self, value):
        return memoryview(value)

    def test_memview_and_memview(self, memview):
        assert memview == memview[::-1]

    def test_bytes_and_shorter_memview(self, value, memview):
        assert value == memview[:-1]

    def test_shorter_memview_and_bytes(self, value, memview):
        assert memview[:-1] == value

    def test_bytes_and_longer_memview(self, value, memview):
        assert value[:-1] == memview

    def test_longer_memview_and_bytes(self, value, memview):
        assert memview == value[:-1]

    def test_memview_and_str(self, text, memview):
        assert memview == text

    def test_str_and_memview(self, text, memview):
        assert text == memview
