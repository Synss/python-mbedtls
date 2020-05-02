# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""Run-time version information"""

from libc.stdlib cimport malloc, free
from libc.string cimport strcpy

cimport mbedtls.version as _ver

from collections import namedtuple


mbedtls_version = namedtuple("mbedtls_version", "major minor micro")


cdef __version_info():
    """Returns the version as a tuple."""
    cdef unsigned int version = _ver.mbedtls_version_get_number()
    major = version >> 24 & 0xff
    minor = version >> 16 & 0xff
    micro = version >> 8  & 0xff
    assert version & 0xff == 0
    return mbedtls_version(major, minor, micro)


cdef __version():
    """Return the version as a string."""
    cdef char *output = <char *>malloc(18 * sizeof(char))
    cdef bytes buffer
    if not output:
        raise MemoryError()
    try:
        _ver.mbedtls_version_get_string_full(output)
        buffer = output
        return buffer.decode("ascii")
    finally:
        free(output)


cdef _has_feature(feature):
    feature_ = feature.encode("ascii")
    cdef char *c_feature = feature_
    cdef int result = _ver.mbedtls_version_check_feature(&c_feature[0])
    if result == -2:
        raise ValueError("%s not supported" % feature)
    return result == 0


def has_feature(feature):
    feature = feature.upper()
    if not feature.startswith("MBEDTLS_"):
        feature = "MBEDTLS_" + feature
    result = _has_feature(feature)
    if result is True:
        return result
    elif not feature.endswith("_C"):
        return _has_feature(feature + "_C")
    else:
        return False


version_info = __version_info()
version = __version()
