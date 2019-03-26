"""Advanced Encryption Standard (AES) cipher established by the U.S.
NIST in 2001.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport mbedtls.cipher._cipher as _cipher
import mbedtls.cipher._cipher as _cipher
from mbedtls.exceptions import *


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
    if mode in {
        _cipher.MODE_ECB,
        _cipher.MODE_CBC,
        _cipher.MODE_CFB,
        _cipher.MODE_OFB,
        _cipher.MODE_CTR,
        _cipher.MODE_GCM,
        _cipher.MODE_CCM
    }:
        if len(key) not in {16, 24, 32}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key))
    elif mode is _cipher.MODE_XTS:
        if len(key) not in {32, 64}:
            raise TLSError(
                msg="key size must 32, or 64 bytes, got %i" % len(key))
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    mode_name = _cipher._get_mode_name(mode)
    if mode is _cipher.MODE_CFB:
        mode_name += "128"
    if mode is _cipher.MODE_XTS:
        name = ("AES-%i-%s" % (len(key) * 4, mode_name)).encode("ascii")
    else:
        name = ("AES-%i-%s" % (len(key) * 8, mode_name)).encode("ascii")
    if mode in {_cipher.MODE_GCM, _cipher.MODE_CCM}:
        return _cipher.AEADCipher(name, key, mode, iv, ad)
    else:
        return _cipher.Cipher(name, key, mode, iv)
