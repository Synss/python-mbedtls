# SPDX-License-Identifier: MIT
# Copyright (c) 2019, Stephen Y.

"""Salsa20 and the closely related ChaCha are stream ciphers
developed by Daniel J. Bernstein.

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


block_size: Final = 1
key_size: Final = 32


@overload
def new(
    key: bytes,
    mode: Literal[Mode.STREAM],
    iv: Optional[bytes] = ...,
) -> Cipher:
    ...


@overload
def new(
    key: bytes,
    mode: Literal[Mode.CHACHAPOLY],
    iv: Optional[bytes] = ...,
    ad: Optional[bytes] = ...,
) -> AEADCipher:
    ...


def new(
    key: bytes,
    mode: Union[Literal[Mode.STREAM], Literal[Mode.CHACHAPOLY], int],
    iv: Optional[bytes] = None,
    ad: Optional[bytes] = None,
) -> Union[Cipher, AEADCipher]:
    """Return a `Cipher` object that can perform ChaCha20 encryption and
    decryption.

    ChaCha was created by Daniel Bernstein as a variant of
    its Salsa cipher https://cr.yp.to/chacha/chacha-20080128.pdf
    ChaCha20 is the variant with 20 rounds, that was also standardized
    in RFC 7539.

    Parameters:
        key: The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode: The mode of operation of the cipher.
        iv: The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.
        ad: The associated data for ChaCha/Poly mode.

    """
    mode_ = Mode(mode)
    if len(key) != key_size:
        raise TLSError(msg="key size must 32 bytes, got %r" % len(key))
    if mode_ == Mode.STREAM:
        assert ad is None
        return Cipher(b"CHACHA20", key, mode_, iv)
    if mode_ == Mode.CHACHAPOLY:
        ad = b"" if ad is None else ad
        return AEADCipher(b"CHACHA20-POLY1305", key, mode_, iv, ad)
    raise TLSError(msg="unsupported mode %r" % mode_)
