"""This module defines exceptions and errors."""


__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2015, Elaborated Networks GmbH"
__license__ = "MIT License"


__all__ = ("CipherError", "InvalidInputLengthError", "InvalidKeyLengthError",
           "EntropyError", "MessageDigestError", "PkError",
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


class Asn1Error(_ErrorBase):
    """Errors defined in `asn1.h`."""


class Base64Error(_ErrorBase):
    """Errors defined in `base64.h`."""


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


class PkError(_ErrorBase):
    """Errors defined in the pk module."""


class PemError(PkError):
    """Errors defined in the pem module."""


class RsaError(PkError):
    """Errors defined in the rsa module."""


class EcError(PkError):
    """Errors defined in the ecp module."""


__lookup = {
    # Blowfish-specific
    0x0016: (InvalidKeyLengthError, "invalid key length"),
    0x0018: (InvalidInputLengthError, "invalid data input length"),
    # Base64
    0x002a: (Base64Error, "output buffer too small"),
    0x002c: (Base64Error, "invalid character in input"),
    # DES
    0x0032: (InvalidInputLengthError, "the data input has an invalid length"),
    # Entropy
    0x003C: (EntropyError, "critical entropy source failure"),
    0x003D: (EntropyError, "no strong source have been added to poll"),
    0x003E: (EntropyError, "no more source can be added"),
    0x003F: (EntropyError, "read/write error in file"),
    0x0040: (EntropyError, "no sources have been added to poll"),
    # ASN1
    0x0060: (Asn1Error, "out of data when parsing and ASN1 data structure"),
    0x0062: (Asn1Error, "ASN.1 tag was of an unexpected value"),
    0x0064: (Asn1Error,
             "error when trying to determine the length" +
             "or invalid length"),
    0x0066: (Asn1Error, "actual length differs from expected length"),
    0x0068: (Asn1Error, "data is invalid"),
    0x006A: (Asn1Error, "memory allocation failed"),
    0x006c: (Asn1Error, "buffer too small when writing ASN.1 data structure"),
    # PEM errors
    0x1080: (PemError, "no PEM header or footer found"),
    0x1100: (PemError, "PEM string is not as expected"),
    0x1180: (PemError, "failed to allocate memory"),
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
    0x3f80: (PkError, "memory allocation failed"),
    0x3f00: (PkError,
             "type mismatch, eg attempt to encrypt with an ECDSA key"),
    0x3e80: (PkError, "bad input parameters to function"),
    0x3e00: (PkError, "read/write of file failed"),
    0x3d80: (PkError, "unsupported key version"),
    0x3d00: (PkError, "invalid key tag or value"),
    0x3c80: (PkError,
             "key algorithm is unsupported" +
             "(only RSA and EC are supported)"),
    0x3c00: (PkError, "private key password can't be empty"),
    0x3b80: (PkError,
             "given private key password does not allow" +
             "for correct decryption"),
    0x3b00: (PkError,
             "the pubkey tag or value is invalid" +
             "(only RSA and EC are supported)"),
    0x3a80: (PkError, "the algorithm tag or value is invalid"),
    0x3a00: (PkError,
             "elliptic curve is unsupported" +
             "(only NIST curves are supported)"),
    0x3980: (PkError,
             "unavailable feature, eg RSA disabled for RSA key"),
    0x3900: (PkError,
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
    0x4d80: (EcError, "memory allocation failed"),
    0x4d00: (EcError,
             "generation of random value, such as (ephemeral) key, failed"),
    0x4c80: (EcError, "invalid private or public key"),
    0x4c00: (EcError,
             "signature is valid but shorter than the user-specified length"),
    # MD errors
    0x5080: (MessageDigestError, "the selected feature is not available"),
    0x5100: (MessageDigestError, "bad input parameter to function"),
    0x5180: (MessageDigestError, "failed to allocate memory"),
    0x5200: (MessageDigestError, "opening or reading of file failed"),
    # Cipher errors
    0x6080: (CipherError, "the selected feature is not available"),
    0x6100: (CipherError, "bad input parameter to function"),
    0x6180: (CipherError, "failed to allocate memory"),
    0x6200: (CipherError, "input contains invalid padding and is rejected"),
    0x6280: (CipherError, "decryption of block requires a full block"),
    0x6300: (CipherError, "authentication failed (for AEAD modes)"),
}


cpdef check_error(const int err):
    if err < 0:
        exc, msg = __lookup.get(-err, (_ErrorBase, ""))
        raise exc(-err, msg)
