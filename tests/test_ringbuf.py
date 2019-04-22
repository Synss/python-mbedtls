from random import randint

import pytest

from mbedtls._ringbuf import RingBuffer


class TestRingBuf:
    @pytest.fixture(params=[2000, 16384])
    def maxlen(self, request):
        return request.param

    @pytest.fixture(params=[10, 100, 1000, 1997, 1998, 1999, 2000])
    def chunk_size(self, request):
        return request.param

    @pytest.fixture
    def buffer(self, maxlen):
        return RingBuffer(maxlen)

    @pytest.fixture
    def randomize_start(self, buffer, maxlen, randbytes):
        # Randomize start of the buffer.
        size = randint(0, maxlen)
        buffer.write(randbytes(size))
        consumed = buffer.consume(size)
        assert buffer.empty()
        assert consumed == size

    def test_initial_conditions(self, buffer, maxlen):
        assert not buffer
        assert len(buffer) == 0
        assert buffer.maxlen == maxlen
        assert buffer.empty()
        assert not buffer.full()

        assert buffer == b""

    @pytest.mark.usefixtures("randomize_start")
    def test_clear(self, buffer, maxlen, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)
        buffer.clear()

        assert written == maxlen
        assert not buffer
        assert len(buffer) == 0
        assert buffer.maxlen == maxlen
        assert buffer.empty()
        assert not buffer.full()

        assert buffer == b""

    @pytest.mark.usefixtures("randomize_start")
    def test_write_empty(self, buffer):
        written = buffer.write(b"")
        assert not written
        assert not buffer
        assert len(buffer) == 0
        assert buffer.empty()
        assert not buffer.full()

        assert buffer == b""

    @pytest.mark.usefixtures("randomize_start")
    def test_consume_zero(self, buffer, maxlen, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)
        buffer.consume(0)

        assert buffer.full()
        assert buffer == data

    @pytest.mark.usefixtures("randomize_start")
    def test_peek_zero(self, buffer, maxlen, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)

        peeked = buffer.peek(0)
        assert peeked == b""

        assert buffer.full()
        assert buffer == data

    @pytest.mark.usefixtures("randomize_start")
    def test_read_zero(self, buffer, maxlen, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)

        assert written == maxlen
        assert buffer.read(0) == b""

    @pytest.mark.usefixtures("randomize_start")
    def test_write_full(self, buffer, maxlen, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)
        assert written == maxlen
        assert buffer
        assert len(buffer) == maxlen
        assert buffer.maxlen == maxlen
        assert not buffer.empty()
        assert buffer.full()

        assert buffer == data

    @pytest.mark.usefixtures("randomize_start")
    def test_write_chunks(self, buffer, maxlen, chunk_size, randbytes):
        data = randbytes(maxlen)
        written = 0
        for index in range(0, maxlen, chunk_size):
            written += buffer.write(data[index : index + chunk_size])

        assert written == maxlen
        assert buffer.full()
        assert buffer == data

    @pytest.mark.usefixtures("randomize_start")
    def test_peek(self, buffer, maxlen, chunk_size, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)
        for index in range(0, maxlen, chunk_size):
            assert buffer.peek(index) == data[0:index]

        assert written == maxlen
        assert buffer == data

    @pytest.mark.usefixtures("randomize_start")
    def test_read_chunks(self, buffer, maxlen, chunk_size, randbytes):
        data = randbytes(maxlen)
        written = buffer.write(data)
        for index in range(0, maxlen, chunk_size):
            assert len(buffer) == maxlen - index
            assert buffer.read(chunk_size) == data[index : index + chunk_size]
        assert written == maxlen
        assert buffer.empty()

    @pytest.mark.usefixtures("randomize_start")
    def test_read_write_with_wraparound(
        self, buffer, maxlen, chunk_size, randbytes
    ):
        wraparound = 5
        written = 0
        for _ in range(wraparound * maxlen // chunk_size):
            data = randbytes(chunk_size)
            written += buffer.write(data)
            assert buffer.read(chunk_size) == data
            assert buffer.empty()
        assert written >= maxlen * (wraparound - 1)

    @pytest.mark.usefixtures("randomize_start")
    def test_read_write_with_wraparound_long(self, buffer, maxlen, randbytes):
        size = randint(2, 42) * maxlen
        step = randint(1, maxlen)
        written = 0
        for idx in range(0, size, step):
            data = randbytes(step)
            amt = buffer.write(data)
            written += amt
            assert amt == step
            assert amt == len(data)
            assert written % step == 0
            assert buffer.read(len(data)) == data
            assert buffer.empty()

    @pytest.mark.usefixtures("randomize_start")
    def test_write_overflow_raises_buffererror(
        self, buffer, maxlen, randbytes
    ):
        data = randbytes(maxlen + 1)
        with pytest.raises(BufferError):
            buffer.write(data)
        assert not buffer
