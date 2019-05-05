"""HMAC-based key derivation function (HKDF).

The HMAC-based extract-and-expand key derivation function specified
by RFC 5869.

"""
__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls._md as _hmac
cimport mbedtls.hkdf as _hkdf

import mbedtls.hmac as _hmac
from mbedtls.exceptions import *


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
    cdef unsigned char *okm = <unsigned char *>malloc(
        length * sizeof(unsigned char)
    )
    if not okm:
        raise MemoryError()
    try:
        check_error(_hkdf.mbedtls_hkdf(
            hmac._info,
            NULL if salt is None or salt.size == 0 else &salt[0],
            0 if salt is None else salt.size,
            &key[0], key.size,
            NULL if info.size == 0 else &info[0],
            0 if info is None else info.size,
            okm, length
        ))
        return bytes(okm[:length])
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
    cdef unsigned char *prk = <unsigned char *>malloc(
        hmac.digest_size * sizeof(unsigned char)
    )
    if not prk:
        raise MemoryError()
    try:
        check_error(_hkdf.mbedtls_hkdf_extract(
            hmac._info,
            NULL if salt is None or not salt.size else &salt[0],
            0 if salt is None else salt.size,
            &key[0], key.size,
            prk
        ))
        return bytes(prk[:hmac.digest_size])
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
    assert hmac.digest_size
    cdef unsigned char *okm = <unsigned char *>malloc(
        length * sizeof(unsigned char)
    )
    if not okm:
        raise MemoryError()
    try:
        check_error(_hkdf.mbedtls_hkdf_expand(
            hmac._info,
            &prk[0], prk.size,
            NULL if not info.size else &info[0],
            0 if info is None else info.size,
            okm, length
        ))
        return bytes(okm[:length])
    finally:
        free(okm)
