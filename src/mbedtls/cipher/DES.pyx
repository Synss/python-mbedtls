"""Data Encryption Standard (DES) cipher developed by IBM
in the 70's."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"


cimport mbedtls.cipher._cipher as _cipher
import mbedtls.cipher._cipher as _cipher
from mbedtls.exceptions import *


MODE_ECB = _cipher.MODE_ECB
MODE_CBC = _cipher.MODE_CBC
# MODE_CFB = _cipher.MODE_CFB
# MODE_OFB = _cipher.MODE_OFB
# MODE_CTR = _cipher.MODE_CTR
# MODE_GCM = _cipher.MODE_GCM
# MODE_STREAM = _cipher.MODE_STREAM
# MODE_CCM = _cipher.MODE_CCM


block_size = 8
key_size = 8


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform DES encryption and
    decryption.

    Data Encryption Standard (DES) cipher developed by IBM in the 70's.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    if len(key) != key_size:
        raise TLSError(msg="key size must be 16 bytes, got %r" % len(key))
    if mode not in {
        _cipher.MODE_ECB,
        _cipher.MODE_CBC,
    }:
        raise TLSError(msg="unsupported mode %r" % mode)
    mode_name = _cipher._get_mode_name(mode)
    name = ("DES-%s" % mode_name).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
