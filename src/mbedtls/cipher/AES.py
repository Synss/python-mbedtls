# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""Advanced Encryption Standard (AES) cipher established by the U.S.
NIST in 2001.

"""


from mbedtls.exceptions import TLSError  # type: ignore

from ._cipher import AEADCipher, Cipher, Mode

__all__ = ["block_size", "key_size", "new"]


block_size = 16
key_size = None


def new(key, mode, iv=None, ad=None):
    """Return a `Cipher` object that can perform AES encryption and
    decryption.

    Advanced Encryption Standard (AES) cipher established by the U.S.
    NIST in 2001.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    mode = Mode(mode)
    if mode in {
        Mode.ECB,
        Mode.CBC,
        Mode.CFB,
        Mode.OFB,
        Mode.CTR,
        Mode.GCM,
        Mode.CCM,
    }:
        if len(key) not in {16, 24, 32}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    elif mode is Mode.XTS:
        if len(key) not in {32, 64}:
            raise TLSError(
                msg="key size must 32, or 64 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    if mode is Mode.XTS:
        name = ("AES-%i-%s" % (len(key) * 4, mode.name)).encode("ascii")
    else:
        name = (
            "AES-%i-%s%s"
            % (
                len(key) * 8,
                mode.name,
                "128" if mode is Mode.CFB else "",
            )
        ).encode("ascii")
    if mode in {Mode.GCM, Mode.CCM}:
        return AEADCipher(name, key, mode, iv, ad)
    return Cipher(name, key, mode, iv)
