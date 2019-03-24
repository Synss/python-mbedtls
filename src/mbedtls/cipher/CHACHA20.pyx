cimport mbedtls.cipher._cipher as _cipher
import mbedtls.cipher._cipher as _cipher
from mbedtls.exceptions import *


block_size = 1
key_size = 32


def new(key, mode, iv=None, ad=None):
    if len(key) != 32:
        raise TLSError(msg="key size must 32 bytes, got %r" % len(key))
    if mode == _cipher.MODE_STREAM:
        assert ad is None
        cipher = _cipher.Cipher(b"CHACHA20", key, mode, iv)
    elif mode == _cipher.MODE_CHACHAPOLY:
        ad = b"" if ad is None else ad
        cipher = _cipher.AEADCipher(b"CHACHA20-POLY1305", key, mode, iv, ad)
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    return cipher
