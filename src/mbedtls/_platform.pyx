# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Platform utils."""


cimport mbedtls._platform as _plt


__all__ = ["zeroize"]


def zeroize(char[:] buffer not None):
    _plt.mbedtls_platform_zeroize(&buffer[0], buffer.size)


def __self_test():
    binary = bytearray(b"0123456789abcdef")
    cdef unsigned char[:] c_binary = binary
    zeroize(c_binary)
    assert binary == b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", binary

    string = bytearray(b"0123456789abcdef")
    cdef char[:] c_string = string
    zeroize(c_string)
    assert string == b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", string
