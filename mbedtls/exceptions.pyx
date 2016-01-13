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
                                    self.err, self.msg)


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


class PrivateKeyError(_ErrorBase):
    """Errors defined in the pk module."""


class PemError(PrivateKeyError):
    """Errors defined in the pem module."""


class RsaError(PrivateKeyError):
    """Errors defined in the rsa module."""


class EcError(PrivateKeyError):
    """Errors defined in the ecp module."""


__lookup = {
    # Blowfish-specific
    0x0016: (InvalidKeyLengthError, "invalid key length"),
    0x0018: (InvalidInputLengthError, "invalid input length"),
    # DES
    0x0032: (InvalidInputLengthError, "invalid input length"),
    # Entropy
    0x003C: (EntropyError, "critical entropy source failure"),
    0x003D: (EntropyError, "no strong source have been added to poll"),
    0x003E: (EntropyError, "no more source can be added"),
    0x003F: (IOError, ""),
    0x0040: (EntropyError, "no sources have been added to poll"),
    # PEM errors
    0x1080: (PemError, "no PEM header or footer found"),
    0x1100: (PemError, "PEM string is not as expected"),
    0x1180: (MemoryError, "failed to allocate memory"),
    0x1200: (PemError, "RSA IV is not in hex-format"),
    0x1280: (PemError, "unsupported key encryption algorithm"),
    0x1300: (PemError, "private key password can't be empty"),
    0x1380: (PemError,
             "given private key password does not allow for" +
             "correct decryption"),
    0x1400: (PemError,
             "unavailable feature, e.g. hashing/decryption combination"),
    0x1480: (PemError, "bad input parameters to function"),
    # PK errors
    0x3f80: (MemoryError, "allocation failed"),
    0x3f00: (PrivateKeyError, "type mismatch"),
    0x3e80: (PrivateKeyError, "bad input data"),
    0x3e00: (IOError, ""),
    0x3d80: (PrivateKeyError, "unsupported key version"),
    0x3d00: (PrivateKeyError, "invalid key tag or value"),
    0x3c80: (PrivateKeyError,
             "key algorithm is unsupported" +
             "(only RSA and EC are supported)"),
    0x3c00: (PrivateKeyError, "private key password can't be empty"),
    0x3b80: (PrivateKeyError,
             "given private key password does not allow" +
             "for correct decryption"),
    0x3b00: (PrivateKeyError,
             "the pubkey tag or value is invalid" +
             "(only RSA and EC are supported)"),
    0x3a80: (PrivateKeyError, "the algorithm tag or value is invalid"),
    0x3a00: (PrivateKeyError,
             "elliptic curve is unsupported" +
             "(only NIST curves are supported)"),
    0x3980: (PrivateKeyError, "feature unavailable"),
    0x3900: (PrivateKeyError,
             "the signature is valid but its length" +
             "is less than expected"),
    # RSA errors
    0x4080: (RsaError, "bad input parameters to function"),
    0x4100: (RsaError, "input data contains invalid padding and is rejected"),
    0x4180: (RsaError, "something failed during generation of a key"),
    0x4200: (RsaError, "key failed to pass the library's validity check"),
    0x4280: (RsaError, "the public key operation failed"),
    0x4300: (RsaError, "the private key operation failed"),
    0x4380: (RsaError, "the PKCS#1 verification failed"),
    0x4400: (RsaError,
             "the output buffer for decryption is not large enough"),
    0x4480: (RsaError, "the random generator failed to generate non-zeros"),
    # ECP errors
    0x4f80: (EcError, "bad input parameters to function"),
    0x4f00: (EcError, "the buffer is too small to write to"),
    0x4e80: (EcError, "requested curve not available"),
    0x4e00: (EcError, "the signature is not valid"),
    0x4d80: (MemoryError, "memory allocation failed"),
    0x4d00: (EcError,
             "generation of random value, such as (ephemeral) key, failed"),
    0x4c80: (EcError, "invalid private or public key"),
    0x4c00: (EcError,
             "signature is valid but shorter than the user-specified length"),
    # MD errors
    0x5080: (MessageDigestError, "feature unavailable"),
    0x5100: (MessageDigestError, "bad input data"),
    0x5180: (MemoryError, "allocation failed"),
    0x5200: (IOError, ""),
    # Cipher errors
    0x6080: (CipherError, "feature unavailable"),
    0x6100: (CipherError, "bad input data"),
    0x6180: (MemoryError, "allocation failed"),
    0x6200: (CipherError, "invalid padding"),
    0x6280: (CipherError, "full block expected"),
    0x6300: (CipherError, "authentication failed"),
}


cpdef check_error(const int err):
    if err < 0:
        exc, msg = __lookup.get(-err, (_ErrorBase, ""))
        raise exc(-err, msg)
