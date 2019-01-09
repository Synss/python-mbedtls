"""A ring buffer.

See Also:
    https://github.com/dhess/c-ringbuf/ Drew Hess' ring
    buffer C implementation was a great help in the
    development of this module.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cimport mbedtls._ringbuf as _rb

import cython


cdef c_init(_rb.ring_buffer_ctx *ctx, size_t maxlen):
    # ringbuf_new()
    ctx._size = maxlen + 1
    ctx.buf = <unsigned char *>malloc(ctx._size * sizeof(unsigned char))
    if not ctx.buf:
        raise MemoryError()
    ctx.head = ctx.tail = ctx.buf


cdef void c_free(_rb.ring_buffer_ctx *ctx) nogil:
    # ringbuf_free()
    free(ctx.buf)
    ctx.head = ctx.tail = NULL


cdef void c_clear(_rb.ring_buffer_ctx *ctx) nogil:
    # ringbuf_reset()
    ctx.head = ctx.tail


cdef size_t c_capacity(_rb.ring_buffer_ctx *ctx) nogil:
    # ringbuf_capacity()
    return ctx._size - 1


cdef unsigned char * c_end(ring_buffer_ctx * ctx) nogil:
    # ringbuf_end()
    return &ctx.buf[ctx._size]


cdef size_t c_len(ring_buffer_ctx *ctx) nogil:
    # ringbuf_bytes_used()
    if ctx.head >= ctx.tail:
        return ctx.head - ctx.tail
    else:
        return c_capacity(ctx) - (ctx.tail - ctx.head - 1)


cdef c_peek(ring_buffer_ctx *ctx, size_t amt):
    cdef unsigned char *dst = <unsigned char *>malloc(
        min(amt, c_len(ctx) * sizeof(unsigned char)))
    if not dst:
        raise MemoryError()
    try:
        nread = c_peekinto(ctx, dst, amt)
        return bytes(dst[:nread])
    finally:
        free(dst)


@cython.boundscheck(False)
cdef size_t c_peekinto(
        ring_buffer_ctx *ctx, unsigned char *dst, size_t amt) nogil:
    cdef size_t size = min(amt, c_len(ctx))
    cdef size_t nread = 0
    cdef unsigned char * index = ctx.tail
    while nread != size:
        if index == c_end(ctx):
            index = ctx.buf

        amt = min(<size_t>(c_end(ctx) - index), size - nread)
        memcpy(&dst[nread], index, amt)
        index += amt
        nread += amt

    return nread


cdef c_read(ring_buffer_ctx *ctx, size_t amt):
    cdef unsigned char *dst = <unsigned char *>malloc(
        min(amt, c_len(ctx)) * sizeof(unsigned char))
    if not dst:
        raise MemoryError()
    try:
        nread = c_readinto(ctx, dst, amt)
        return bytes(dst[:nread])
    finally:
        free(dst)


@cython.boundscheck(False)
cdef size_t c_readinto(
        ring_buffer_ctx *ctx, unsigned char *dst, size_t amt) nogil:
    # ringbuf_memcpy_from()
    cdef size_t size = min(amt, c_len(ctx))
    cdef size_t nread = 0
    while nread != size:
        if ctx.tail == c_end(ctx):
            ctx.tail = ctx.buf

        amt = min(<size_t>(c_end(ctx) - ctx.tail), size - nread)
        memcpy(&dst[nread], ctx.tail, amt)
        ctx.tail += amt
        nread += amt

    return nread


cdef size_t c_consume(ring_buffer_ctx *ctx, size_t amt) nogil:
    cdef size_t size = min(amt, c_len(ctx))
    cdef size_t nconsumed = 0
    while nconsumed != size:
        if ctx.tail == c_end(ctx):
            ctx.tail = ctx.buf

        amt = min(<size_t>(c_end(ctx) - ctx.tail), size - nconsumed)
        ctx.tail += amt
        nconsumed += amt

    return nconsumed


@cython.boundscheck(False)
cdef size_t c_write(
        ring_buffer_ctx *ctx, const unsigned char *src, size_t amt) nogil:
    # ringbuf_memcpy_into()
    cdef size_t size = amt
    # if size > c_capacity(ctx) - c_len(ctx):
    #     raise BufferError("Buffer overflow")

    cdef size_t nwritten = 0
    while nwritten != size:
        if ctx.head == c_end(ctx):
            ctx.head = ctx.buf

        amt = min(<size_t>(c_end(ctx) - ctx.head), size - nwritten)
        memcpy(ctx.head, &src[nwritten], amt)
        ctx.head += amt
        nwritten += amt

    return nwritten


cdef class RingBuffer:
    def __cinit__(self, size_t maxlen):
        c_init(&self._ctx, maxlen)

    def __dealloc__(self):
        c_free(&self._ctx)

    @property
    def maxlen(self):
        return c_capacity(&self._ctx)

    def __eq__(self, other):
        # Call `__bytes__()` directly for Python 2.7.
        try:
            return self.__bytes__() == other.__bytes__()
        except AttributeError:
            return self.__bytes__() == bytes(other)

    def __len__(self):
        return c_len(&self._ctx)

    def __bool__(self):
        return not self.empty()

    def __bytes__(self):
        return self.peek(len(self))

    def clear(self):
        c_clear(&self._ctx)

    def full(self):
        return len(self) == self.maxlen

    def empty(self):
        return len(self) == 0

    def peek(self, size_t amt):
        return c_peek(&self._ctx, amt)

    def read(self, size_t amt):
        return c_read(&self._ctx, amt)

    def consume(self, size_t amt):
        return c_consume(&self._ctx, amt)

    def write(self, const unsigned char[:] src, amt=None):
        if src.size == 0:
            return 0
        if amt is None:
            amt = src.size
        else:
            amt = min(src.size, amt)
        if amt > self.maxlen - len(self):
            raise BufferError("Buffer overflow")
        return c_write(&self._ctx, &src[0], amt)
