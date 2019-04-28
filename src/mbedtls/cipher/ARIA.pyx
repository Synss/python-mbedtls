"""The ARIA algorithm is a symmetric block cipher that can encrypt and
decrypt information. It is defined by the Korean Agency for Technology
and Standards (KATS) in *KS X 1213:2004* (in Korean, but see
http://210.104.33.10/ARIA/index-e.html in English) and also described by
the IETF in *RFC 5794*.

"""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2019, Mathias Laurin"
__license__ = "MIT License"


from . import _cipher
from mbedtls.exceptions import *

__all__ = ["block_size", "key_size", "new"]


block_size = 16
key_size = None


def new(key, mode, iv=None):
    mode = _cipher.Mode(mode)
    if mode in {
        _cipher.Mode.ECB,
        _cipher.Mode.CBC,
        # _cipher.Mode.CFB128,
        _cipher.Mode.CTR,
        _cipher.Mode.GCM,
        _cipher.Mode.CCM,
    }:
        if len(key) * 8 not in {128, 192, 256}:
            raise TLSError(
                msg="key size must 16, 24, or 32 bytes, got %i" % len(key)
            )
    else:
        raise TLSError(msg="unsupported mode %r" % mode)
    name = ("ARIA-%i-%s" % (len(key) * 8, mode.name)).encode("ascii")
    return _cipher.Cipher(name, key, mode, iv)
