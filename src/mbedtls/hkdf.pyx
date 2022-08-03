# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""HMAC-based key derivation function (HKDF).

The HMAC-based extract-and-expand key derivation function specified
by RFC 5869.

"""


from libc.stdlib cimport free, malloc

cimport mbedtls._md as _hmac
cimport mbedtls.hkdf as _hkdf

import mbedtls.exceptions as _exc
import mbedtls.hmac as _hmac

__all__ = ("hkdf", "extract", "expand")


def hkdf(
    const unsigned char[:] key not None,
    length,
    const unsigned char[:] info not None,
    const unsigned char[:] salt=None,
    digestmod=None,
):
    """HMAC-based extract-and-expand key derivation function (HKDF).

    Arguments:
        key (bytes): The input keying material.
        length (int): The length of the output keying material in bytes.
        info (bytes): Additional context and application specific information.
        salt (bytes, optional): A non-secret random value.
        digestmod (hmac function, optional): The HMAC function to use for
            the extraction, defaults to SHA256.

    """
    if key.size == 0:
        key = b"\0"
    if digestmod is None:
        digestmod = _hmac.sha256
    cdef _hmac.Hmac hmac = digestmod(key)

    cdef const unsigned char *c_info
    if info.size == 0:
        c_info = NULL
    else:
        c_info = &info[0]
    cdef const unsigned char *c_salt
    if salt is None or salt.size == 0:
        c_salt = NULL
    else:
        c_salt = &salt[0]

    cdef unsigned char *okm = <unsigned char *>malloc(
        length * sizeof(unsigned char)
    )

    if not okm:
        raise MemoryError()
    try:
        _exc.check_error(_hkdf.mbedtls_hkdf(
            hmac._info,
            c_salt, 0 if salt is None else salt.size,
            &key[0], key.size,
            c_info, 0 if info is None else info.size,
            okm, length
        ))
        return okm[:length]
    finally:
        free(okm)


def extract(
    const unsigned char[:] key not None,
    const unsigned char[:] salt=None,
    digestmod=None,
):
    """Extract a fixed-length pseudorandom key.

    This function extracts a fixed-length pseudorandom key from
    its input keying material.

    This function should only be used if the security of it has been
    studied and established in that particular context (eg. TLS 1.3 key
    schedule).  For standard HKDF security guarantees use `hkdf` instead.

    Arguments:
        key (bytes): The input keying material.
        salt (bytes, optional): A non-secret random value.
        digestmod (hmac function, optional): The HMAC function to use for
            the extraction, defaults to SHA256.

    """
    if key.size == 0:
        key = b"\0"
    if digestmod is None:
        digestmod = _hmac.sha256
    cdef _hmac.Hmac hmac = digestmod(key)

    cdef const unsigned char *c_key
    if key.size == 0:
        c_key = NULL
    else:
        c_key = &key[0]
    cdef const unsigned char *c_salt
    if salt is None or salt.size == 0:
        c_salt = NULL
    else:
        c_salt = &salt[0]

    cdef unsigned char *prk = <unsigned char *>malloc(
        hmac.digest_size * sizeof(unsigned char)
    )
    if not prk:
        raise MemoryError()
    try:
        _exc.check_error(_hkdf.mbedtls_hkdf_extract(
            hmac._info,
            c_salt, 0 if salt is None else salt.size,
            c_key, key.size,
            prk
        ))
        return prk[:hmac.digest_size]
    finally:
        free(prk)


def expand(
    const unsigned char[:] prk not None,
    length,
    const unsigned char[:] info not None,
    digestmod=None,
):
    """Expand the pseudorandom key `prk` into additional pseudorandom keys.

    This function should only be used if the security of it has been
    studied and established in that particular context (eg. TLS 1.3 key
    schedule).  For standard HKDF security guarantees use `hkdf` instead.

    Arguments:
        prk (bytes): The pseudorandom key to expand, usually the
            output of `extract()`.
        length (int): The length of the output keying material in bytes.
        info (bytes): Additional context and application specific information.
        digestmod (hmac function, optional): The HMAC function to use for
            the extraction, defaults to SHA256.

    """
    if prk.size == 0:
        prk = b"\0"
    if digestmod is None:
        digestmod = _hmac.sha256
    cdef _hmac.Hmac hmac = digestmod(prk)

    cdef const unsigned char *c_info
    if info.size == 0:
        c_info = NULL
    else:
        c_info = &info[0]

    cdef unsigned char *okm = <unsigned char *>malloc(
        length * sizeof(unsigned char)
    )
    if not okm:
        raise MemoryError()
    try:
        _exc.check_error(_hkdf.mbedtls_hkdf_expand(
            hmac._info,
            &prk[0], prk.size,
            c_info, 0 if info is None else info.size,
            okm, length
        ))
        return okm[:length]
    finally:
        free(okm)
