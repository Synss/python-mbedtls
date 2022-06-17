# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Mathias Laurin

"""The ARIA algorithm is a symmetric block cipher that can encrypt and
decrypt information. It is defined by the Korean Agency for Technology
and Standards (KATS) in *KS X 1213:2004* (in Korean, but see
http://210.104.33.10/ARIA/index-e.html in English) and also described by
the IETF in *RFC 5794*.

"""

import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

from typing import Optional, Union

from mbedtls.exceptions import TLSError

from ._cipher import Cipher, Mode

__all__ = ["block_size", "key_size", "new"]


block_size: Final = 16
key_size: Final = None


def new(
    key: bytes,
    mode: Union[int, Literal[Mode.CBC, Mode.CTR, Mode.ECB, Mode.GCM]],
    iv: Optional[bytes] = None,
) -> Cipher:
    """Return a `Cipher` object that can perform ARIA encryption and
    decryption.

    ARIA is a block cipher designed in 2003 by a large group of South
    Korean researchers. In 2004, the Korean Agency for Technology and
    Standards selected it as a standard cryptographic technique.

    Parameters:
        key: The key to encrypt decrypt.
        mode: The mode of operation of the cipher.
        iv: The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode_ = Mode(mode)
    if mode_ in {
        Mode.CBC,
        # Mode.CFB128,
        Mode.CTR,
        Mode.ECB,
        Mode.GCM,
    }:
        if len(key) * 8 not in {128, 192, 256}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode_)
    name = ("ARIA-%i-%s" % (len(key) * 8, mode_.name)).encode("ascii")
    return Cipher(name, key, mode_, iv)
