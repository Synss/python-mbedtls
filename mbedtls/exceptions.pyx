"""This module defines exceptions and errors."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


__all__ = ("CipherError", "InvalidInputLengthError", "InvalidKeyLengthError",
           "EntropyError", "MessageDigestError",
           "check_error",
           )


class _ErrorBase(ValueError):
    """Base class for cipher exceptions."""

    def __init__(self, err=None, msg="", *args):
        super().__init__(*args)
        self.err = err
        self.msg = msg

    def __str__(self):
        return "%s([0x%04X] %s)" % (self.__class__.__name__,
                                    abs(self.err), self.msg)


class CipherError(_ErrorBase):
    """Errors defined in the cipher module."""


class InvalidInputLengthError(CipherError):
    """Invalid input length."""


class InvalidKeyLengthError(CipherError):
    """Invalid key length."""


class EntropyError(_ErrorBase):
    """Errors defined in the entropy module."""


class MessageDigestError(_ErrorBase):
    """Errors defined in the md module."""


__lookup = {
    # Blowfish-specific
    -0x0016: (InvalidKeyLengthError, "invalid key length"),
    -0x0018: (InvalidInputLengthError, "invalid input length"),
    # DES
    -0x0032: (InvalidInputLengthError, "invalid input length"),
    # Entropy
    -0x003C: (EntropyError, "critical entropy source failure"),
    -0x003D: (EntropyError, "no strong source have been added to poll"),
    -0x003E: (EntropyError, "no more source can be added"),
    -0x003F: (IOError, ""),
    -0x0040: (EntropyError, "no sources have been added to poll"),
    # MD errors
    -0x5080: (MessageDigestError, "feature unavailable"),
    -0x5100: (MessageDigestError, "bad input data"),
    -0x5180: (MemoryError, "allocation failed"),
    -0x5200: (IOError, ""),
    # Cipher errors
    -0x6080: (CipherError, "feature unavailable"),
    -0x6100: (CipherError, "bad input data"),
    -0x6180: (MemoryError, "allocation failed"),
    -0x6200: (CipherError, "invalid padding"),
    -0x6280: (CipherError, "full block expected"),
    -0x6300: (CipherError, "authentication failed"),
}


cpdef check_error(const int err):
    if not err:
        return
    else:
        exc, msg = __lookup.get(err, (_ErrorBase, ""))
        raise exc(err, msg)
