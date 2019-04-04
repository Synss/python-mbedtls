"""The ARIA algorithm is a symmetric block cipher that can encrypt and
decrypt information. It is defined by the Korean Agency for Technology
and Standards (KATS) in *KS X 1213:2004* (in Korean, but see
http://210.104.33.10/ARIA/index-e.html in English) and also described by
the IETF in *RFC 5794*.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


cimport mbedtls.cipher._cipher as _cipher
import mbedtls.cipher._cipher as _cipher
from mbedtls.exceptions import *


block_size = 16
key_size = None


def new(key, mode, iv=None):
    if mode in {
        _cipher.MODE_ECB,
        _cipher.MODE_CBC,
        # _cipher.MODE_CFB128,
        _cipher.MODE_CTR,
        _cipher.MODE_GCM,
        _cipher.MODE_CCM,
    }:
        if len(key) * 8 not in {128, 192, 256}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    mode_name = _cipher._get_mode_name(mode)
    name = ("ARIA-%i-%s" % (len(key) * 8, mode_name)).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
