"""Advanced Encryption Standard (AES) cipher established by the U.S.
NIST in 2001.

"""

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
MODE_GCM = _cipher.MODE_GCM
# MODE_STREAM = _cipher.MODE_STREAM
MODE_CCM = _cipher.MODE_CCM


class Aes(_cipher.Cipher):

    """Advanced Encryption Standard (AES) cipher established by the U.S.
    NIST in 2001.

    Parameters:
        key (bytes or None): The key to encrypt decrypt.  If None,
            encryption and decryption are unavailable.
        mode (int): The mode of operation of the cipher.
        iv (bytes or None): The initialization vector (IV).  The IV is
            required for every mode but ECB and CTR where it is ignored.
            If not set, the IV is initialized to all 0, which should not
            be used for encryption.

    Attributes:
        block_size (int): The block size for the cipher in bytes.
        iv_size (int): The size of the cipher's IV/NONCE in bytes.
        key_size (int): The size of the cipher's key, in bytes.

    """
    def __init__(self, key, mode, iv=None):
        bitlength = len(key) * 8
        if bitlength not in {128, 192, 256}:
            raise InvalidKeyLengthError(
                "bitlength must 128, 192, or 256, got %r" % bitlength)
        if mode not in {MODE_ECB, MODE_CBC, MODE_CFB, MODE_CTR,
                        MODE_GCM, MODE_CCM}:
            raise FeatureUnavailableError("unsupported mode %r" % mode)
        mode_name = _cipher._get_mode_name(mode)
        if mode is MODE_CFB:
            mode_name += "128"
        name = ("AES-%i-%s" % (bitlength, mode_name)).encode("ascii")
        super().__init__(name, key, iv)
