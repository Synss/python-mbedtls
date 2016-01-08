"""This module defines exceptions and errors."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "Apache License 2.0"


__all__ = ("AllocFailedError",
           "InvalidKeyLengthError", 
           "InvalidInputLengthError",
           "InvalidPaddingError",
           "FeatureUnavailableError",
           "BadInputDataError",
           "FullBlockExpectedError",
           "AuthFailedError",
           "UnsupportedCipherError",
           "check_error",
           )


class AllocFailedError(MemoryError):
    """Exception raised when allocation failed."""


class _ErrorBase(Exception):
    """Base class for cipher exceptions."""


class InvalidKeyLengthError(_ErrorBase):
    """Raised for invalid key length."""


class InvalidInputLengthError(_ErrorBase):
    """Raised for invalid input length."""


class InvalidPaddingError(_ErrorBase):
    """Raised for invalid padding."""


class FeatureUnavailableError(_ErrorBase):
    """Raised when calling a feature that is not available."""


class BadInputDataError(_ErrorBase):
    """Raised for bad input data."""


class FullBlockExpectedError(_ErrorBase):
    """Raised when encryption expects full blocks."""


class AuthFailedError(_ErrorBase):
    """Raised when authentication failed."""


class UnsupportedCipherError(_ErrorBase):
    """Raised upon trying to instantiate an unsupported cipher."""


cpdef check_error(const int err):
    if not err:
        return
    else:
        raise {
            # Blowfish-specific
            -0x0016: InvalidKeyLengthError,
            -0x0018: InvalidInputLengthError,
            # DES
            -0x0032: InvalidInputLengthError,
            # MD errors
            -0x5080: FeatureUnavailableError,
            -0x5100: BadInputDataError,
            -0x5180: AllocFailedError,
            -0x5200: IOError,
            # Cipher errors
            -0x6080: FeatureUnavailableError,
            -0x6100: BadInputDataError,
            -0x6180: AllocFailedError,
            -0x6200: InvalidPaddingError,
            -0x6280: FullBlockExpectedError,
            -0x6300: AuthFailedError,
        }.get(err, _ErrorBase)()
