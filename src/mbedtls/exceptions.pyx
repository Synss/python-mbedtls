"""This module defines exceptions and errors."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"

from libc.stdlib cimport malloc, free

cimport mbedtls.exceptions as _err


__all__ = ("TLSError", "check_error")


class TLSError(Exception):
    """Exception raise by Mbed TLS."""

    def __init__(self, err=None, msg=""):
        super(TLSError, self).__init__()
        if err is not None:
            assert err >= 0
        self.err = err
        self._msg = msg

    @property
    def msg(self):
        if self.err is None:
            return self._msg

        # Set buflen to 200 as in `strerror.c`.
        cdef size_t buflen = 200
        cdef char* buffer = <char*>malloc(buflen * sizeof(char))
        if not buffer:
            raise MemoryError()
        try:
            _err.mbedtls_strerror(self.err, &buffer[0], buflen)
            output = bytes(buffer[:buflen])
            try:
                olen = output.index(b"\0")
            except ValueError:
                olen = buflen
            return output[:olen].decode("ascii")
        finally:
            free(buffer)

    def __str__(self):
        if self.err is None:
            return "%s(%s)" % (type(self).__name__, self.msg)
        else:
            return "%s([0x%04X] %r)" % (self.__class__.__name__,
                                        self.err, self.msg)


cpdef check_error(const int err):
    if err >= 0:
        return err
    raise TLSError(-err)
