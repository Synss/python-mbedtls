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

cimport mbedtls._dhm as _dhm
cimport mbedtls._ecdh as _ecdh
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
            return cls(key=bkey, password=password())
        return cls(key=bkey, password=password)

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

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        raise NotImplementedError

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        raise NotImplementedError

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
        if not self._has_private():
            return b""
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
        finally:
            free(output)

    def _private_to_PEM(self):
        if not self._has_private():
            return ""
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
        finally:
            free(output)

    def export_key(self, format="DER"):
        """Return the private key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER" or "PEM".

        """
        if format == "DER":
            return self._private_to_DER()
        if format == "PEM":
            return self._private_to_PEM()
        raise ValueError(format)

    def _public_to_DER(self):
        if not self._has_public():
            return b""
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
        if not self._has_public():
            return ""
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
            return self._public_to_DER()
        if format == "PEM":
            return self._public_to_PEM()
        raise ValueError(format)

    def to_PEM(self):
        """Return the RSA in PEM format.

        Warning:
            This function is obsolete.

        Return:
            tuple(str, str): The private key and the public key.

        See Also:
            export_key(), export_public_key()

        """
        return KeyPair(self.export_key("PEM"), self.export_public_key("PEM"))

    def __str__(self):
        return self.export_key(format="PEM")

    def to_DER(self):
        """Return the RSA in DER format.

        Warning:
            This function is obsolete.

        Return:
            tuple(bytes, bytes): The private key and the public key.

        See Also:
            export_key(), export_public_key()

        """
        return KeyPair(self.export_key("DER"), self.export_public_key("DER"))

    def to_bytes(self):
        """Return the private key in DER format."""
        return self.export_key(format="DER")

    def __bytes__(self):
        return self.to_bytes()


cdef class RSA(CipherBase):

    """RSA public-key cryptosystem."""

    def __init__(self,
                 const unsigned char[:] key=None,
                 const unsigned char[:] password=None):
        super().__init__(b"RSA", key, password)

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _rsa.mbedtls_rsa_check_privkey(
            _pk.mbedtls_pk_rsa(self._ctx)
        ) == 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        return _rsa.mbedtls_rsa_check_pubkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

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
        return self.export_key("DER")


cdef class ECPoint:

    """A point on the elliptic curve."""
    def __init__(self, x, y, z):
        cdef _mpi.MPI _x = _mpi.MPI(x)
        cdef _mpi.MPI _y = _mpi.MPI(y)
        cdef _mpi.MPI _z = _mpi.MPI(z)
        _mpi.mbedtls_mpi_copy(&self._ctx.X, &_x._ctx)
        _mpi.mbedtls_mpi_copy(&self._ctx.Y, &_y._ctx)
        _mpi.mbedtls_mpi_copy(&self._ctx.Z, &_z._ctx)

    def __cinit__(self):
        """Initialize the context."""
        _ecp.mbedtls_ecp_point_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _ecp.mbedtls_ecp_point_free(&self._ctx)

    def __reduce__(self):
        return type(self), (self.x, self.y, self.z)

    @property
    def x(self):
        """Return the X coordinate."""
        try:
            return _mpi.from_mpi_p(&self._ctx.X)
        except ValueError:
            return _mpi.MPI()

    @property
    def y(self):
        """Return the Y coordinate."""
        try:
            return _mpi.from_mpi_p(&self._ctx.Y)
        except ValueError:
            return _mpi.MPI()

    @property
    def z(self):
        """Return the Z coordinate."""
        try:
            return _mpi.from_mpi_p(&self._ctx.Z)
        except ValueError:
            return _mpi.MPI()

    def __str__(self):
        return "%s(%i, %i, %i)" % (
            type(self).__name__, self.x, self.y, self.z
        )

    def __repr__(self):
        return "%s(%r, %r, %r)" % (
            type(self).__name__, self.x, self.y, self.z
        )

    def __eq__(self, other):
        if other == 0:
            return _ecp.mbedtls_ecp_is_zero(&self._ctx) == 1
        elif type(other) is type(self):
            c_other = <ECPoint> other
            return _ecp.mbedtls_ecp_point_cmp(&self._ctx, &c_other._ctx) == 0
        return NotImplemented

    def __hash__(self):
        return hash((self.x, self.y, self.z))

    def __bool__(self):
        return _ecp.mbedtls_ecp_is_zero(&self._ctx) == 0


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

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        cdef const _ecp.mbedtls_ecp_keypair* ecp = _pk.mbedtls_pk_ec(self._ctx)
        return _mpi.mbedtls_mpi_cmp_mpi(&ecp.d, &_mpi.MPI()._ctx) != 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        cdef _ecp.mbedtls_ecp_keypair* ecp = _pk.mbedtls_pk_ec(self._ctx)
        return not _ecp.mbedtls_ecp_is_zero(&ecp.Q)

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
        format = (
            "NUM"
            if self.curve in (Curve.CURVE25519, Curve.CURVE448)
            else "DER"
        )
        return self.export_key(format)

    def _private_to_num(self):
        try:
            return _mpi.from_mpi_p(&_pk.mbedtls_pk_ec(self._ctx).d)
        except ValueError:
            return _mpi.MPI()

    def export_key(self, format=None):
        """Return the private key.

        If not key is present, return a falsy value.

        Args:
            format (str): One of "DER", "PEM", or "NUM".

        """
        if format is None:
            format = (
                "NUM"
                if self.curve in (Curve.CURVE25519, Curve.CURVE448)
                else "DER"
            )
        if format == "NUM":
            return self._private_to_num()
        elif self.curve in (Curve.CURVE25519, Curve.CURVE448):
            raise ValueError(
                "Curve25519 and Curve448 only support export as NUM"
            )
        return super().export_key(format)

    def _public_to_point(self):
        point = ECPoint(0, 0, 0)
        _ecp.mbedtls_ecp_copy(&point._ctx, &_pk.mbedtls_pk_ec(self._ctx).Q)
        return point

    def export_public_key(self, format="DER"):
        """Return the public key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER", "PEM", or "POINT".

        """
        if format == "POINT":
            return self._public_to_point()
        elif self.curve in (Curve.CURVE25519, Curve.CURVE448):
            raise ValueError(
                "Curve25519 and Curve448 only support export as NUM"
            )
        return super().export_public_key(format)


cdef class DHBase:

    """Base class to DH key exchange: client and server.

    Args:
        modulus (int): The prime modulus P.
        generator (int): The generator G, a primitive root modulo P.

    See Also:
        DHServer, DHClient: The derived classes.

    """
    def __init__(self, modulus, generator):
        super().__init__()
        _exc.check_error(_mpi.mbedtls_mpi_copy(
            &self._ctx.P, &_mpi.MPI(modulus)._ctx))
        _exc.check_error(_mpi.mbedtls_mpi_copy(
            &self._ctx.G, &_mpi.MPI(generator)._ctx))

    def __cinit__(self):
        """Initialize the context."""
        _dhm.mbedtls_dhm_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _dhm.mbedtls_dhm_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    @property
    def key_size(self):
        """Return the size of the key, in bytes."""
        return _mpi.mbedtls_mpi_size(&self._ctx.P)

    @property
    def modulus(self):
        """Return the prime modulus, P."""
        return _mpi.from_mpi_p(&self._ctx.P)

    @property
    def generator(self):
        """Return the generator, G."""
        return _mpi.from_mpi_p(&self._ctx.G)

    @property
    def _secret(self):
        """Return the secret (int)."""
        return _mpi.from_mpi_p(&self._ctx.X)

    @property
    def shared_secret(self):
        """The shared secret (int).

        The shared secret is 0 if the TLS handshake is not finished.

        """
        try:
            return _mpi.from_mpi_p(&self._ctx.K)
        except ValueError:
            return _mpi.MPI()

    def generate_secret(self):
        """Generate the shared secret."""
        cdef _mpi.MPI mpi
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_dhm.mbedtls_dhm_calc_secret(
                &self._ctx, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE, &olen,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            mpi = _mpi.MPI()
            _mpi.mbedtls_mpi_read_binary(&mpi._ctx, &output[0], olen)
            return mpi
        finally:
            free(output)


cdef class DHServer(DHBase):

    """The server side of the DH key exchange."""

    def generate(self):
        """Generate a public key.

        Return:
            bytes: A TLS ServerKeyExchange payload.

        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_dhm.mbedtls_dhm_make_params(
                &self._ctx, self.key_size, &output[0], &olen,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)

    def import_CKE(self, const unsigned char[:] buffer not None):
        """Read the ClientKeyExchange payload."""
        if buffer.size == 0:
            buffer = b"\0"
        _exc.check_error(_dhm.mbedtls_dhm_read_public(
            &self._ctx, &buffer[0], buffer.size))


cdef class DHClient(DHBase):

    """The client side of the DH key exchange."""

    def generate(self):
        """Generate the public key.

        Return:
            bytes: The byte representation (big endian) of: G^X mod P.

        """
        cdef _mpi.MPI mpi
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_dhm.mbedtls_dhm_make_public(
                &self._ctx, self.key_size, &output[0], self.key_size,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            mpi = _mpi.from_mpi_p(&self._ctx.GX)
            return mpi.to_bytes(
                _mpi.mbedtls_mpi_size(&mpi._ctx), "big")
        finally:
            free(output)

    def import_SKE(self, const unsigned char[:] buffer not None):
        """Read the ServerKeyExchange payload."""
        if buffer.size == 0:
            raise ValueError("SKE is empty")
        # Const away cast is safe because the pointer is used as
        # a read-only index in `dhm_read_bignum()`.
        cdef unsigned char* first = <unsigned char*> &buffer[0]
        cdef const unsigned char* end = &buffer[-1] + 1
        _exc.check_error(_dhm.mbedtls_dhm_read_params(&self._ctx, &first, end))


cdef class ECDHBase:

    """Base class to ECDH(E) key exchange: client and server.

    Args:
        (Curve, optional): A curve returned by `get_supported_curves()`.

    See Also:
        ECDHServer, ECDHClient: The derived class.
        get_supported_curves()

    """
    def __init__(self, curve=None):
        super().__init__()
        if curve is None:
            curve = get_supported_curves()[0]
        self.curve = Curve(curve)
        _exc.check_error(_ecp.mbedtls_ecp_group_load(
            &self._ctx.grp, curve_name_to_grp_id(self.curve)))

    def __cinit__(self):
        """Initialize the context."""
        _ecdh.mbedtls_ecdh_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _ecdh.mbedtls_ecdh_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _mpi.mbedtls_mpi_cmp_mpi(&self._ctx.d, &_mpi.MPI()._ctx) != 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        return not _ecp.mbedtls_ecp_is_zero(&self._ctx.Q)

    def _has_peers_public(self):
        """Return `True` if the peer's key is present."""
        return not _ecp.mbedtls_ecp_is_zero(&self._ctx.Qp)

    @property
    def public_key(self):
        """The public key (ECPoint)"""
        ecp = ECPoint(0, 0, 0)
        _exc.check_error(_ecp.mbedtls_ecp_copy(&ecp._ctx, &self._ctx.Q))
        return ecp

    @public_key.setter
    def public_key(self, ECPoint ecp):
        _exc.check_error(_ecp.mbedtls_ecp_copy(&self._ctx.Q, &ecp._ctx))

    @property
    def private_key(self):
        """The private key (int)"""
        return _mpi.from_mpi_p(&self._ctx.d)

    @private_key.setter
    def private_key(self, priv):
        cdef _mpi.MPI c_priv = _mpi.MPI(priv)
        _mpi.mbedtls_mpi_copy(&self._ctx.d, &c_priv._ctx)

    @property
    def peers_public_key(self):
        """Peer's public key (ECPoint)"""
        ecp = ECPoint(0, 0, 0)
        _exc.check_error(_ecp.mbedtls_ecp_copy(&ecp._ctx, &self._ctx.Qp))
        return ecp

    @peers_public_key.setter
    def peers_public_key(self, ECPoint ecp):
        _exc.check_error(_ecp.mbedtls_ecp_copy(&self._ctx.Qp, &ecp._ctx))

    @property
    def shared_secret(self):
        """The shared secret (int).

        The shared secret is 0 if the TLS handshake is not finished.

        """
        try:
            return _mpi.from_mpi_p(&self._ctx.z)
        except ValueError:
            return _mpi.MPI()

    def generate_secret(self):
        """Generate the shared secret."""
        cdef _mpi.MPI mpi = _mpi.MPI()
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecdh.mbedtls_ecdh_calc_secret(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            curve_type = _ecp.mbedtls_ecp_get_type(&self._ctx.grp)
            if curve_type == _ecp.MBEDTLS_ECP_TYPE_MONTGOMERY:
                _mpi.mbedtls_mpi_read_binary_le(&mpi._ctx, &output[0], olen)
            else:
                _mpi.mbedtls_mpi_read_binary(&mpi._ctx, &output[0], olen)
            return mpi
        finally:
            free(output)

    def generate_public_key(self):
        """Generate public key from a private key."""
        _exc.check_error(_ecp.mbedtls_ecp_mul(
            &self._ctx.grp, &self._ctx.Q, &self._ctx.d, &self._ctx.grp.G,
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))


cdef class ECDHServer(ECDHBase):

    """The server side of the ECDH key exchange."""

    def __init__(self, ecc: ECC):
        super().__init__(ecc.curve)
        if ecc.export_key():
            _exc.check_error(_ecdh.mbedtls_ecdh_get_params(
                &self._ctx, _pk.mbedtls_pk_ec(ecc._ctx), _ecdh.MBEDTLS_ECDH_OURS))

    def generate(self):
        """Generate a public key.

        Return:
            bytes: A TLS ServerKeyExchange payload.

        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecdh.mbedtls_ecdh_make_params(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)

    def import_CKE(self, const unsigned char[:] buffer not None):
        """Read the ClientKeyExchange payload."""
        if buffer.size == 0:
            buffer = b"\0"
        _exc.check_error(_ecdh.mbedtls_ecdh_read_public(
            &self._ctx, &buffer[0], buffer.size))


cdef class ECDHClient(ECDHBase):

    """The client side of the ephemeral ECDH key exchange."""

    def __init__(self, ecc: ECC):
        super().__init__(ecc.curve)
        if ecc.export_key():
            _exc.check_error(_ecdh.mbedtls_ecdh_get_params(
                &self._ctx, _pk.mbedtls_pk_ec(ecc._ctx), _ecdh.MBEDTLS_ECDH_THEIRS))

    def generate(self):
        """Generate a public key.

        Return:
            bytes: A TLS ClientKeyExchange payload.

        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecdh.mbedtls_ecdh_make_public(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)

    def import_SKE(self, const unsigned char[:] buffer not None):
        """Read the ServerKeyExchange payload."""
        if buffer.size == 0:
            buffer = b"\0"
        cdef const unsigned char* first = &buffer[0]
        cdef const unsigned char* end = &buffer[-1] + 1
        _exc.check_error(_ecdh.mbedtls_ecdh_read_params(
            &self._ctx, &first, end))


cdef class ECDHNaive(ECDHBase):

    """Naive ECDH key exchange."""

    def __init__(self, curve=None):
        if curve is None:
            curve = Curve.CURVE25519
        curve = Curve(curve)
        if curve not in {Curve.CURVE25519, Curve.CURVE448}:
            raise ValueError("ECDHNaive only supports curve25519 and curve448")
        super().__init__(curve)

    def generate(self):
        """Generate a public key.

        Return:
            ECPoint: public key.

        """
        _exc.check_error(_ecdh.mbedtls_ecdh_gen_public(
            &self._ctx.grp, &self._ctx.d, &self._ctx.Q,
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
        return self.public_key

    def import_peer_public(self, pubkey):
        self.import_peers_public(pubkey.x)

    def import_peers_public(self, _pk.ECPoint pubkey):
        """Read peer public key."""
        _exc.check_error(_ecp.mbedtls_ecp_copy(&self._ctx.Qp, &pubkey._ctx))

    def generate_secret(self):
        """Generate the shared secret."""
        _exc.check_error(_ecdh.mbedtls_ecdh_compute_shared(
            &self._ctx.grp, &self._ctx.z, &self._ctx.Qp, &self._ctx.d,
            &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
        return _mpi.from_mpi_p(&self._ctx.z)
