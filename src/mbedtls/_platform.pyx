# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Platform utils."""


cimport mbedtls._platform as _plt

__all__ = ["zeroize"]


def zeroize(char[:] buffer not None):
    _plt.mbedtls_platform_zeroize(&buffer[0], buffer.size)
