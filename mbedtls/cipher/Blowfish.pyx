"""Blowfish cipher designed by Bruce Schneier in 1993."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


cimport _cipher
import _cipher
from mbedtls.exceptions import *


MODE_ECB = _cipher.MODE_ECB
MODE_CBC = _cipher.MODE_CBC
MODE_CFB = _cipher.MODE_CFB
# MODE_OFB = _cipher.MODE_OFB
MODE_CTR = _cipher.MODE_CTR
# MODE_GCM = _cipher.MODE_GCM
# MODE_STREAM = _cipher.MODE_STREAM
# MODE_CCM = _cipher.MODE_CCM


def new(key, mode, iv=None):
    """Return a `Cipher` object that can perform Blowfish encryption and
    decryption.

    Blowfish cipher designed by Bruce Schneier in 1993.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    """
    if mode not in {MODE_ECB, MODE_CBC, MODE_CFB, MODE_CTR}:
        raise FeatureUnavailableError("unsupported mode %r" % mode)
    mode_name = _cipher._get_mode_name(mode)
    if mode is MODE_CFB:
        mode_name += "64"
    name = ("BLOWFISH-%s" % mode_name).encode("ascii")
    return _cipher.Cipher(name, key, iv)
