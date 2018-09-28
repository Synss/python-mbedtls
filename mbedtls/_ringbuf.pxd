"""A ring buffer.

See Also:
    https://github.com/dhess/c-ringbuf/

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cdef struct ring_buffer_ctx:
    unsigned char *buf
    unsigned char *head
    unsigned char *tail
    size_t _size


cdef c_init(ring_buffer_ctx *, size_t)
cdef void c_free(ring_buffer_ctx *) nogil
cdef void c_clear(ring_buffer_ctx *) nogil
cdef size_t c_capacity(ring_buffer_ctx *) nogil
cdef size_t c_len(ring_buffer_ctx *) nogil
cdef c_peek(ring_buffer_ctx *, size_t)
cdef size_t c_peekinto(ring_buffer_ctx *, unsigned char *, size_t) nogil
cdef c_read(ring_buffer_ctx *, size_t)
cdef size_t c_readinto(ring_buffer_ctx *, unsigned char *,  size_t) nogil
cdef size_t c_consume(ring_buffer_ctx *, size_t) nogil
cdef size_t c_write(ring_buffer_ctx *, const unsigned char *, size_t) nogil


cdef class RingBuffer:
    cdef ring_buffer_ctx _ctx
