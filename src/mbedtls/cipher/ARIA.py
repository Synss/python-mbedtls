# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""The ARIA algorithm is a symmetric block cipher that can encrypt and
decrypt information. It is defined by the Korean Agency for Technology
and Standards (KATS) in *KS X 1213:2004* (in Korean, but see
http://210.104.33.10/ARIA/index-e.html in English) and also described by
the IETF in *RFC 5794*.

"""


from mbedtls.exceptions import TLSError

from . import _cipher

__all__ = ["block_size", "key_size", "new"]


block_size = 16
key_size = None


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform ARIA encryption and
    decryption.

    ARIA is a block cipher designed in 2003 by a large group of South
    Korean researchers. In 2004, the Korean Agency for Technology and
    Standards selected it as a standard cryptographic technique.

    Parameters:
        key (bytes): The key to encrypt decrypt.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode = _cipher.Mode(mode)
    if mode in {
        _cipher.Mode.ECB,
        _cipher.Mode.CBC,
        # _cipher.Mode.CFB128,
        _cipher.Mode.CTR,
        _cipher.Mode.GCM,
    }:
        if len(key) * 8 not in {128, 192, 256}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = ("ARIA-%i-%s" % (len(key) * 8, mode.name)).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
