# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

"""Public key (PK) library.

The library handles RSA certificates and ECC (elliptic curve
cryptography).

The RSA and ECC classes offer compatible APIs.  They may be used
interchangeably.

ECDHServer and ECDHClient should be used for ephemeral Elliptic Curve
Diffie-Hellman exchange.

"""


from libc.stdlib cimport free, malloc
from libc.string cimport memset

cimport mbedtls._ecp as _ecp
cimport mbedtls._random as _rnd
cimport mbedtls._rsa as _rsa
cimport mbedtls.mpi as _mpi
cimport mbedtls.pk as _pk

import enum
import re
from collections import namedtuple
from functools import partial
from pathlib import Path

import mbedtls._random as _rnd
import mbedtls.exceptions as _exc
from mbedtls.hashlib import new as _new_hash

__all__ = ("check_pair", "get_supported_ciphers", "get_supported_curves",
           "Curve", "RSA", "ECC", "DHServer", "DHClient",
           "ECDHServer", "ECDHClient", "ECDHNaive")


CIPHER_NAME = (
    b"NONE",
    b"RSA",
    b"EC",
    b"EC_DH",
    b"ECDSA",
    # b"RSA_ALT",
    # b"RSASSA_PSS",
)


class CipherType(enum.Enum):
    NONE = _pk.MBEDTLS_PK_NONE
    RSA = _pk.MBEDTLS_PK_RSA
    ECKEY = _pk.MBEDTLS_PK_ECKEY
    ECKEY_DH = _pk.MBEDTLS_PK_ECKEY_DH
    ECDSA = _pk.MBEDTLS_PK_ECDSA
    RSA_ALT = _pk.MBEDTLS_PK_RSA_ALT
    RSASSA_PSS = _pk.MBEDTLS_PK_RSASSA_PSS


KeyPair = namedtuple("KeyPair", ["private", "public"])


class Curve(bytes, enum.Enum):

    """Elliptic curves."""

    SECP192R1 = b'secp192r1'
    SECP224R1 = b'secp224r1'
    SECP256R1 = b'secp256r1'
    SECP384R1 = b'secp384r1'
    SECP521R1 = b'secp521r1'
    BRAINPOOLP256R1 = b'brainpoolP256r1'
    BRAINPOOLP384R1 = b'brainpoolP384r1'
    BRAINPOOLP512R1 = b'brainpoolP512r1'
    SECP192K1 = b'secp192k1'
    SECP224K1 = b'secp224k1'
    SECP256K1 = b'secp256k1'
    CURVE25519 = b'x25519'
    CURVE448 = b'x448'


# The following calculations come from mbedtls/library/pkwrite.c.
RSA_PUB_DER_MAX_BYTES = 38 + 2 * _mpi.MBEDTLS_MPI_MAX_SIZE
MPI_MAX_SIZE_2 = _mpi.MBEDTLS_MPI_MAX_SIZE // 2 + _mpi.MBEDTLS_MPI_MAX_SIZE % 2
RSA_PRV_DER_MAX_BYTES = 47 + 3 * _mpi.MBEDTLS_MPI_MAX_SIZE + 5 * MPI_MAX_SIZE_2

ECP_PUB_DER_MAX_BYTES = 30 + 2 * _ecp.MBEDTLS_ECP_MAX_BYTES
ECP_PRV_DER_MAX_BYTES = 29 + 3 * _ecp.MBEDTLS_ECP_MAX_BYTES

PUB_DER_MAX_BYTES = max(RSA_PUB_DER_MAX_BYTES, ECP_PUB_DER_MAX_BYTES)
PRV_DER_MAX_BYTES = max(RSA_PRV_DER_MAX_BYTES, ECP_PRV_DER_MAX_BYTES)

del RSA_PUB_DER_MAX_BYTES, MPI_MAX_SIZE_2, RSA_PRV_DER_MAX_BYTES
del ECP_PUB_DER_MAX_BYTES, ECP_PRV_DER_MAX_BYTES


cpdef check_pair(CipherBase pub, CipherBase pri):
    """Check if a public-private pair of keys matches."""
    return _pk.mbedtls_pk_check_pair(&pub._ctx, &pri._ctx) == 0


def _type_from_name(name):
    return {name: n for n, name in enumerate(CIPHER_NAME)}.get(name, 0)


cpdef get_supported_ciphers():
    return CIPHER_NAME


def get_supported_curves():
    """Return the list of supported curves in order of preference."""
    cdef const _ecp.mbedtls_ecp_curve_info* info = _ecp.mbedtls_ecp_curve_list()
    names, idx = [], 0
    while info[idx].name != NULL:
        names.append(Curve(bytes(info[idx].name)))
        idx += 1
    return names


cdef curve_name_to_grp_id(curve):
    cdef const _ecp.mbedtls_ecp_curve_info* info = _ecp.mbedtls_ecp_curve_list()
    idx = 0
    while info[idx].name != NULL:
        if info[idx].name == curve:
            return info[idx].grp_id
        idx += 1
    raise LookupError(curve.decode("ascii") + " not found")


cdef _rnd.Random __rng = _rnd.default_rng()


def _get_md_alg(digestmod):
    """Return the hash object.

    Arguments:
        digestmod: The digest name or digest constructor for the
            Cipher object to use.  It supports any name suitable to
            `mbedtls.hash.new()`.

    """
    # `digestmod` handling below is adapted from CPython's
    # `hmac.py`.
    if callable(digestmod):
        return digestmod
    elif isinstance(digestmod, (str, unicode)):
        return partial(_new_hash, digestmod)
    else:
        raise TypeError("a valid digestmod is required, got %r" % digestmod)


class CipherState(enum.Flag):
    UNSET = enum.auto()
    PUBLIC = enum.auto()
    PRIVATE = enum.auto()


cdef class CipherBase:
    """Base class to RSA and ECC ciphers.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.
        key (bytes, optional): A key (public or private half).
        password (bytes, optional): The password for the key.

    """
    def __init__(self,
                 name,
                 const unsigned char[:] key=None,
                 const unsigned char[:] password=None):
        self.__state = CipherState.UNSET
        _exc.check_error(_pk.mbedtls_pk_setup(
            &self._ctx,
            _pk.mbedtls_pk_info_from_type(
                _type_from_name(name)
            )
        ))
        if key is None or key.size == 0:
            return
        mbedtls_pk_free(&self._ctx)  # The context must be reset on entry.
        try:
            if password is None or password.size == 0:
                _exc.check_error(_pk.mbedtls_pk_parse_key(
                    &self._ctx, &key[0], key.size, NULL, 0
                ))
            else:
                _exc.check_error(_pk.mbedtls_pk_parse_key(
                    &self._ctx, &key[0], key.size, &password[0], password.size
                ))
        except _exc.TLSError:
            _exc.check_error(_pk.mbedtls_pk_parse_public_key(
                &self._ctx, &key[0], key.size))
        pub = self._public_to_PEM()
        if "PUBLIC" in pub:
            self.__state |= CipherState.PUBLIC
        if _pk.mbedtls_pk_check_pair(&self._ctx, &self._ctx) == 0:
            self.__state |= CipherState.PRIVATE

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_pk_init(&self._ctx)

    def __reduce__(self):
        key = self.export_key()
        if not key:
            key = self.export_public_key()
        return type(self).from_buffer, (key,)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_pk_free(&self._ctx)

    def __hash__(self):
        if self._has_private():
            return hash(self.export_key(format="DER"))
        else:
            return hash(self.export_public_key(format="DER"))

    def __eq__(self, other):
        if isinstance(other, str):
            other = other.encode("ascii")
        if isinstance(other, bytes):
            try:
                other = type(self).from_buffer(other)
            except (_exc.TLSError, ValueError, TypeError):
                return False
        if type(other) is not type(self):
            return False
        if self._has_private() or other._has_private():
            return other.export_key() == self.export_key()
        elif not (self._has_private() and other._has_private()):
            return other.export_public_key() == self.export_public_key()

    def __str__(self):
        return self.export_key(format="PEM")

    def __bytes__(self):
        return self.to_bytes()

    def to_bytes(self):
        """Return the private key in DER format."""
        return self.export_key(format="DER")

    @classmethod
    def from_buffer(
        cls,
        const unsigned char[:] key not None,
        password=None,
    ):
        """Import a key (public or private half).

        The public half is generated upon importing a private key.

        Arguments:
            key (bytes): The key in PEM or DER format.
            password (bytes, optional): The password for
                password-protected private keys.

        """
        bkey = bytes(key)
        if re.search(b"^-----BEGIN.+END.+-----\\s+$", bkey, re.DOTALL):
            # PEM must be null-terminated.
            bkey = bkey + b"\0"
        if callable(password):
            self = cls(key=bkey, password=password())
        else:
            self = cls(key=bkey, password=password)
        return self

    @classmethod
    def from_file(cls, path, password=None):
        return cls.from_buffer(Path(path).read_bytes(), password)

    @classmethod
    def from_DER(cls, const unsigned char[:] key not None):
        return cls.from_buffer(key)

    @classmethod
    def from_PEM(cls, key):
        """Import a key (public or private half)."""
        return cls.from_buffer(key.encode("ascii"))

    @property
    def _type(self):
        """Return the type of the cipher."""
        return _pk.mbedtls_pk_get_type(&self._ctx)

    @property
    def name(self):
        """Return the name of the cipher."""
        return _pk.mbedtls_pk_get_name(&self._ctx)

    @property
    def _bitlen(self):
        """Return the size of the key, in bits."""
        return _pk.mbedtls_pk_get_bitlen(&self._ctx)

    @property
    def key_size(self):
        """Return the size of the key, in bytes."""
        return _pk.mbedtls_pk_get_len(&self._ctx)

    def _set_private(self):
        self.__state |= CipherState.PRIVATE

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        return CipherState.PRIVATE in self.__state

    def _set_public(self):
        self.__state |= CipherState.PUBLIC

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        return CipherState.PUBLIC in self.__state

    def sign(self,
             const unsigned char[:] message not None,
             digestmod=None):
        """Make signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            digestmod (optional): The digest name or digest constructor.

        Return:
            bytes or None: The signature or None if the cipher does not
                contain a private key.

        """
        if digestmod is None:
            digestmod = 'sha256'
        if not self._has_private():
            return None
        md_alg = _get_md_alg(digestmod)(message)
        cdef const unsigned char[:] hash_ = md_alg.digest()
        cdef size_t sig_len = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_pk.mbedtls_pk_sign(
                &self._ctx, md_alg._type,
                &hash_[0], hash_.size,
                &output[0], &sig_len,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert sig_len != 0
            return output[:sig_len]
        finally:
            free(output)

    def verify(self,
               const unsigned char[:] message not None,
               const unsigned char[:] signature not None,
               digestmod=None):
        """Verify signature, including padding if relevant.

        Arguments:
            message (bytes): The message to sign.
            signature (bytes): The signature to verify.
            digestmod (optional): The digest name or digest constructor.

        Return:
            bool: True if the verification passed, False otherwise.

        """
        if signature.size == 0:
            return False
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(message)
        cdef const unsigned char[:] hash_ = md_alg.digest()
        return _pk.mbedtls_pk_verify(
            &self._ctx, md_alg._type,
            &hash_[0], hash_.size,
            &signature[0], signature.size) == 0

    def encrypt(self, const unsigned char[:] message not None):
        """Encrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to encrypt.

        """
        if message.size == 0:
            message = b"\0"
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE // 2 * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_pk.mbedtls_pk_encrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            return output[:olen]
        finally:
            free(output)

    def decrypt(self, const unsigned char[:] message not None):
        """Decrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to decrypt.

        """
        if message.size == 0:
            message = b"\0"
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE // 2 * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_pk.mbedtls_pk_decrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            return output[:olen]
        finally:
            free(output)

    def generate(self):
        """Generate a keypair.

        Return:
            (bytes): The private key in DER format.

        """
        raise NotImplementedError

    def _private_to_DER(self):
        cdef int olen
        cdef size_t osize = PRV_DER_MAX_BYTES
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            olen = _exc.check_error(
                _pk.mbedtls_pk_write_key_der(&self._ctx, output, osize))
            return output[osize - olen:osize]
        except _exc.TLSError as exc:
            if exc.err == 0x4080:
                # no private key
                return b""
            raise
        finally:
            free(output)

    def _private_to_PEM(self):
        cdef size_t osize = PRV_DER_MAX_BYTES * 4 // 3 + 100
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        memset(output, 0, osize)
        try:
            _exc.check_error(
                _pk.mbedtls_pk_write_key_pem(&self._ctx, output, osize))
            return output[0:osize].rstrip(b"\0").decode("ascii")
        except _exc.TLSError as exc:
            if exc.err == 0x4080:
                # no private key
                return ""
            raise
        finally:
            free(output)

    def export_key(self, format="DER"):
        """Return the private key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER" or "PEM".

        """
        if format == "DER":
            return self._private_to_DER() if self._has_private() else b""
        if format == "PEM":
            return self._private_to_PEM() if self._has_private() else ""
        raise ValueError(format)

    def _public_to_DER(self):
        cdef int olen
        cdef size_t osize = PRV_DER_MAX_BYTES
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            olen = _exc.check_error(
                _pk.mbedtls_pk_write_pubkey_der(&self._ctx, output, osize))
            return output[osize - olen:osize]
        finally:
            free(output)

    def _public_to_PEM(self):
        cdef size_t osize = PRV_DER_MAX_BYTES * 4 // 3 + 100
        cdef unsigned char *output = <unsigned char *>malloc(
            osize * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        memset(output, 0, osize)
        try:
            _exc.check_error(
                _pk.mbedtls_pk_write_pubkey_pem(&self._ctx, output, osize))
            return output[0:osize].rstrip(b"\0").decode("ascii")
        finally:
            free(output)

    def export_public_key(self, format="DER"):
        """Return the public key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER" or "PEM".

        """
        if format == "DER":
            return self._public_to_DER() if self._has_public() else b""
        if format == "PEM":
            return self._public_to_PEM() if self._has_public() else ""
        raise ValueError(format)


cdef class RSA(CipherBase):

    """RSA public-key cryptosystem."""

    def __init__(self,
                 const unsigned char[:] key=None,
                 const unsigned char[:] password=None):
        super().__init__(b"RSA", key, password)

    def generate(self, unsigned int key_size=2048, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        Return:
            (bytes): The private key in DER format.

        """
        _exc.check_error(_rsa.mbedtls_rsa_gen_key(
            _pk.mbedtls_pk_rsa(self._ctx), &_rnd.mbedtls_ctr_drbg_random,
            &__rng._ctx, key_size, exponent))
        self._set_public()
        self._set_private()
        return self.export_key("DER")


cdef class ECC(CipherBase):

    """Elliptic-curve cryptosystems.

    Args:
        (Curve, optional): A curve returned by `get_supported_curves()`.

    See Also:
        get_supported_curves()

    """
    def __init__(self,
                 curve=None,
                 const unsigned char[:] key=None,
                 const unsigned char[:] password=None):
        super().__init__(b"EC", key, password)
        if curve is None:
            curve = get_supported_curves()[0]
        self._curve = curve

    @property
    def curve(self):
        return self._curve

    def sign(self,
             const unsigned char[:] message not None,
             digestmod=None):
        if self._curve in (Curve.CURVE25519, Curve.CURVE448):
            raise ValueError("ECDSA does not support Curve25519 or Curve448.")
        return super().sign(message, digestmod)

    def generate(self):
        """Generate an EC keypair.

        Return:
            (bytes): The private key in DER format.

        """
        grp_id = curve_name_to_grp_id(self.curve)
        if grp_id is None:
            raise ValueError(self.curve)
        _exc.check_error(_ecp.mbedtls_ecp_gen_key(
            grp_id, _pk.mbedtls_pk_ec(self._ctx),
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
        self._set_public()
        self._set_private()
        return self.export_key("DER")

    def export_key(self, format=None):
        """Return the private key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER", "PEM".

        """
        if format is None:
            format = "DER"
        return super().export_key(format)
