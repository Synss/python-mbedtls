# SPDX-License-Identifier: MIT

from __future__ import annotations

import pickle
from random import randint
from typing import Any, Callable

import pytest

from mbedtls._ringbuf import RingBuffer  # type: ignore


@pytest.fixture()
def randomize_start(
    randbytes: Callable[[int], bytes]
) -> Callable[[bytes], None]:
    def impl(buffer: RingBuffer) -> None:
        # Randomize start of the buffer.
        size = randint(0, buffer.maxlen)
        buffer.write(randbytes(size))
        consumed = buffer.consume(size)
        assert buffer.empty()
        assert consumed == size

    return impl


class TestRingBuf:
    @pytest.fixture(params=[2000, 16384])
    def maxlen(self, request: Any) -> int:
        assert isinstance(request.param, int)
        return request.param

    def test_initial_conditions(self, maxlen: int) -> None:
        buffer = RingBuffer(maxlen)

        assert not buffer
        assert len(buffer) == 0
        assert buffer.maxlen == maxlen
        assert buffer.empty()
        assert not buffer.full()

        assert buffer == b""

    def test_clear(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

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

    def test_write_empty(
        self, maxlen: int, randomize_start: Callable[[bytes], None]
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        written = buffer.write(b"")
        assert not written
        assert not buffer
        assert len(buffer) == 0
        assert buffer.empty()
        assert not buffer.full()

        assert buffer == b""

    def test_pickle(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen // 2)
        assert buffer.write(data) == len(data)

        other = pickle.loads(pickle.dumps(buffer))
        assert other
        assert other == buffer

    def test_consume_zero(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        assert buffer.write(data) == len(data)
        buffer.consume(0)

        assert buffer.full()
        assert buffer == data

    def test_peek_zero(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        assert buffer.write(data) == len(data)

        peeked = buffer.peek(0)
        assert peeked == b""

        assert buffer.full()
        assert buffer == data

    def test_read_zero(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        written = buffer.write(data)

        assert written == maxlen
        assert buffer.read(0) == b""

    def test_write_full(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        written = buffer.write(data)
        assert written == maxlen
        assert buffer
        assert len(buffer) == maxlen
        assert buffer.maxlen == maxlen
        assert not buffer.empty()
        assert buffer.full()

        assert buffer == data

    @pytest.mark.parametrize(
        "chunk_size", [10, 100, 1000, 1997, 1998, 1999, 2000]
    )
    def test_write_chunks(
        self,
        maxlen: int,
        chunk_size: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        written = 0
        for index in range(0, maxlen, chunk_size):
            written += buffer.write(data[index : index + chunk_size])

        assert written == maxlen
        assert buffer.full()
        assert buffer == data

    @pytest.mark.parametrize(
        "chunk_size", [10, 100, 1000, 1997, 1998, 1999, 2000]
    )
    def test_peek(
        self,
        maxlen: int,
        chunk_size: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        written = buffer.write(data)
        for index in range(0, maxlen, chunk_size):
            assert buffer.peek(index) == data[0:index]

        assert written == maxlen
        assert buffer == data

    @pytest.mark.parametrize(
        "chunk_size", [10, 100, 1000, 1997, 1998, 1999, 2000]
    )
    def test_read_chunks(
        self,
        maxlen: int,
        chunk_size: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen)
        written = buffer.write(data)
        for index in range(0, maxlen, chunk_size):
            assert len(buffer) == maxlen - index
            assert buffer.read(chunk_size) == data[index : index + chunk_size]
        assert written == maxlen
        assert buffer.empty()

    @pytest.mark.parametrize(
        "chunk_size", [10, 100, 1000, 1997, 1998, 1999, 2000]
    )
    def test_read_write_with_wraparound(
        self,
        maxlen: int,
        chunk_size: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        wraparound = 5
        written = 0
        for _ in range(wraparound * maxlen // chunk_size):
            data = randbytes(chunk_size)
            written += buffer.write(data)
            assert buffer.read(chunk_size) == data
            assert buffer.empty()
        assert written >= maxlen * (wraparound - 1)

    def test_read_write_with_wraparound_long(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

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

    def test_write_overflow_raises_buffererror(
        self,
        maxlen: int,
        randomize_start: Callable[[bytes], None],
        randbytes: Callable[[int], bytes],
    ) -> None:
        buffer = RingBuffer(maxlen)
        randomize_start(buffer)

        data = randbytes(maxlen + 1)
        with pytest.raises(BufferError):
            buffer.write(data)
        assert not buffer
