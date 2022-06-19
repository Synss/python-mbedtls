# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Advanced Encryption Standard (AES) cipher established by the U.S.
NIST in 2001.

"""

import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal
else:
    from typing import Final, Literal

from typing import Optional, Union, overload

from mbedtls.exceptions import TLSError

from ._cipher import AEADCipher, Cipher, Mode

__all__ = ["block_size", "key_size", "new"]


block_size: Final = 16
key_size: Final = None


@overload
def new(
    key: bytes,
    mode: Literal[Mode.CCM, Mode.GCM],
    iv: Optional[bytes] = ...,
    ad: Optional[bytes] = ...,
) -> AEADCipher:
    ...


@overload
def new(
    key: bytes,
    mode: Literal[Mode.CBC, Mode.CFB, Mode.CTR, Mode.ECB, Mode.OFB, Mode.XTS],
    iv: Optional[bytes] = ...,
) -> Cipher:
    ...


def new(
    key: bytes,
    mode: Union[Mode, int],
    iv: Optional[bytes] = None,
    ad: Optional[bytes] = None,
) -> Union[AEADCipher, Cipher]:
    """Return a `Cipher` object that can perform AES encryption and
    decryption.

    Advanced Encryption Standard (AES) cipher established by the U.S.
    NIST in 2001.

    Parameters:
        key: The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode: The mode of operation of the cipher.
        iv: The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode_ = Mode(mode)
    if mode_ in {
        Mode.CBC,
        Mode.CCM,
        Mode.CFB,
        Mode.CTR,
        Mode.ECB,
        Mode.GCM,
        Mode.OFB,
    }:
        if len(key) not in {16, 24, 32}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    elif mode_ is Mode.XTS:
        if len(key) not in {32, 64}:
            raise TLSError(
                msg="key size must 32, or 64 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode_)
    if mode_ is Mode.XTS:
        name = ("AES-%i-%s" % (len(key) * 4, mode_.name)).encode("ascii")
    else:
        name = (
            "AES-%i-%s%s"
            % (
                len(key) * 8,
                mode_.name,
                "128" if mode_ is Mode.CFB else "",
            )
        ).encode("ascii")
    if mode_ in {Mode.GCM, Mode.CCM}:
        return AEADCipher(name, key, mode_, iv, ad)
    return Cipher(name, key, mode_, iv)
