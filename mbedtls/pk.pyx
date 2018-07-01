"""Public key (PK) library.

The library handles RSA certificates and ECC (elliptic curve
cryptography).

The RSA and ECC classes offer compatible APIs.  They may be used
interchangeably.

ECDHServer and ECDHClient should be used for ephemeral Elliptic Curve
Diffie-Hellman exchange.

"""

__author__ = "Mathias Laurin"
__copyright__ = ("Copyright 2016, Elaborated Networks GmbH, "
                 "Copyright 2018, Mathias Laurin")
__license__ = "MIT License"


from libc.stdlib cimport malloc, free

cimport mbedtls.mpi as _mpi
cimport mbedtls.pk as _pk
cimport mbedtls.random as _random

try:
    from collections.abc import Sequence
except ImportError:
    # Python 2.7
    from collections import Sequence

import enum
from functools import partial

import mbedtls.random as _random
from mbedtls.exceptions import check_error, MbedTLSError
import mbedtls.hash as _hash


__all__ = ("check_pair", "get_supported_ciphers", "get_supported_curves",
           "Curve", "RSA", "ECC", "DHServer", "DHClient",
           "ECDHServer", "ECDHClient")


CIPHER_NAME = (
    b"NONE",
    b"RSA",
    b"EC",
    b"EC_DH",
    b"ECDSA",
    # b"RSA_ALT",
    # b"RSASSA_PSS",
)


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
    CURVE25519 = b'curve25519'
    SECP256K1 = b'secp256k1'
    SECP224K1 = b'secp224k1'
    SECP192K1 = b'secp192k1'


# The following calculations come from mbedtls/library/pkwrite.c.
RSA_PUB_DER_MAX_BYTES = 38 + 2 * _mpi.MBEDTLS_MPI_MAX_SIZE
MPI_MAX_SIZE_2 = _mpi.MBEDTLS_MPI_MAX_SIZE / 2 + _mpi.MBEDTLS_MPI_MAX_SIZE % 2
RSA_PRV_DER_MAX_BYTES = 47 + 3 * _mpi.MBEDTLS_MPI_MAX_SIZE + 5 * MPI_MAX_SIZE_2

ECP_PUB_DER_MAX_BYTES = 30 + 2 * _pk.MBEDTLS_ECP_MAX_BYTES
ECP_PRV_DER_MAX_BYTES = 29 + 3 * _pk.MBEDTLS_ECP_MAX_BYTES

cdef int PUB_DER_MAX_BYTES = max(RSA_PUB_DER_MAX_BYTES, ECP_PUB_DER_MAX_BYTES)
cdef int PRV_DER_MAX_BYTES = max(RSA_PRV_DER_MAX_BYTES, ECP_PRV_DER_MAX_BYTES)

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
    cdef const mbedtls_ecp_curve_info* info = mbedtls_ecp_curve_list()
    names, idx = [], 0
    while info[idx].name != NULL:
        names.append(Curve(bytes(info[idx].name)))
        idx += 1
    return names


cdef curve_name_to_grp_id(name):
    cdef const mbedtls_ecp_curve_info* info = mbedtls_ecp_curve_list()
    idx = 0
    while info[idx].name != NULL:
        if info[idx].name == name:
            return info.grp_id
        idx += 1


cdef _random.Random __rng = _random.Random()


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
        return partial(_hash.new, digestmod)
    else:
        raise TypeError("a valid digestmod is required, got %r" % digestmod)


cdef class CipherBase:
    """Base class to RSA and ECC ciphers.

    Parameters:
        name (bytes): The cipher name known to mbed TLS.

    """
    def __init__(self, name):
        check_error(_pk.mbedtls_pk_setup(
            &self._ctx,
            _pk.mbedtls_pk_info_from_type(
                _type_from_name(name)
            )
        ))

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_pk_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_pk_free(&self._ctx)

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        try:
            return self.to_DER() == other.to_DER()
        except MbedTLSError:
            return False

    property _type:
        """Return the type of the cipher."""
        def __get__(self):
            return _pk.mbedtls_pk_get_type(&self._ctx)
    
    property name:
        """Return the name of the cipher."""
        def __get__(self):
            return _pk.mbedtls_pk_get_name(&self._ctx)

    property _bitlen:
        """Return the size of the key, in bits."""
        def __get__(self):
            return _pk.mbedtls_pk_get_bitlen(&self._ctx)

    property key_size:
        """Return the size of the key, in bytes."""
        def __get__(self):
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
            check_error(_pk.mbedtls_pk_sign(
                &self._ctx, md_alg._type,
                &hash_[0], hash_.size,
                &output[0], &sig_len,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert sig_len != 0
            return bytes(output[:sig_len])
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
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE // 2 * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_encrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes(output[:olen])
        finally:
            free(output)

    def decrypt(self, const unsigned char[:] message not None):
        """Decrypt message (including padding if relevant).

        Arguments:
            message (bytes): Message to decrypt.

        """
        cdef size_t olen = 0
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE // 2 * sizeof(unsigned char))
        if not output:
            raise MemoryError()
        try:
            check_error(_pk.mbedtls_pk_decrypt(
                &self._ctx, &message[0], message.size,
                output, &olen, self.key_size,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            return bytes(output[:olen])
        finally:
            free(output)

    def generate(self):
        """Generate a keypair.

        Return:
            (bytes): The private key in DER format.

        """
        raise NotImplementedError

    cdef bytes _write(self, int (*fun)(_pk.mbedtls_pk_context *,
                                       unsigned char *, size_t),
                      size_t olen):
        cdef unsigned char[:] buf = bytearray(olen * b"\0")
        cdef int ret = fun(&self._ctx, &buf[0], buf.size)
        check_error(ret)
        # DER format: `ret` is the size of the buffer, offset from the end.
        # PEM format: `ret` is zero.
        if not ret:
            ret = olen
        # cast unsigned char[:] -> bytearray -> bytes
        return bytes(bytearray(buf[olen - ret:olen]))

    def from_buffer(self, key, password=None):
        """Import a key (public or private half).

        The public half is generated upon importing a private key.

        Arguments:
            key (bytes): The key in PEM or DER format.
            password (bytes, optional): The password for
                password-protected private keys.

        """
        if password is None:
            password = bytearray()
        cdef unsigned char[:] pwd_ = bytearray(password)
        cdef unsigned char[:] key_ = bytearray(key + b"\0")
        mbedtls_pk_free(&self._ctx)  # The context must be reset on entry.
        try:
            check_error(_pk.mbedtls_pk_parse_key(
                &self._ctx, &key_[0], key_.size,
                &pwd_[0] if pwd_.size else NULL, pwd_.size))
        except MbedTLSError:
            check_error(_pk.mbedtls_pk_parse_public_key(
                &self._ctx, &key_[0], key_.size))

    from_DER = from_buffer

    def from_PEM(self, key, password=None):
        """Import a key (public and private half)."""
        self.from_buffer(key.encode("ascii"), password=password)

    def _private_to_DER(self):
        if not self._has_private():
            return b""
        return self._write(&_pk.mbedtls_pk_write_key_der, PRV_DER_MAX_BYTES)

    def _private_to_PEM(self):
        if not self._has_private():
            return ""
        return self._write(&_pk.mbedtls_pk_write_key_pem,
                           PRV_DER_MAX_BYTES * 4 // 3 + 100).decode("ascii")

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
        return self._write(&_pk.mbedtls_pk_write_pubkey_der, PUB_DER_MAX_BYTES)

    def _public_to_PEM(self):
        if not self._has_public():
            return ""
        return self._write(&_pk.mbedtls_pk_write_pubkey_pem,
                           PUB_DER_MAX_BYTES * 4 // 3 + 100).decode("ascii")

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
        return self.export_key("PEM"), self.export_public_key("PEM")

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
        return self.export_key("DER"), self.export_public_key("DER")

    def to_bytes(self):
        """Return the private key in DER format."""
        return self.export_key(format="DER")

    def __bytes__(self):
        return self.to_bytes()


cdef class RSA(CipherBase):

    """RSA public-key cryptosystem."""

    def __init__(self):
        super().__init__(b"RSA")

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _pk.mbedtls_rsa_check_privkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        return _pk.mbedtls_rsa_check_pubkey(_pk.mbedtls_pk_rsa(self._ctx)) == 0

    def generate(self, unsigned int key_size=2048, int exponent=65537):
        """Generate an RSA keypair.

        Arguments:
            key_size (unsigned int): size in bits.
            exponent (int): public RSA exponent.

        Return:
            (bytes): The private key in DER format.

        """
        check_error(_pk.mbedtls_rsa_gen_key(
            _pk.mbedtls_pk_rsa(self._ctx), &_random.mbedtls_ctr_drbg_random,
            &__rng._ctx, key_size, exponent))
        return self.export_key("DER")


cdef class ECPoint:

    """A point on the elliptic curve."""

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_ecp_point_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_ecp_point_free(&self._ctx)

    property x:
        """Return the X coordinate."""
        def __get__(self):
            try:
                return _mpi.from_mpi(&self._ctx.X)
            except ValueError:
                return _mpi.MPI()

    property y:
        """Return the Y coordinate."""
        def __get__(self):
            try:
                return _mpi.from_mpi(&self._ctx.Y)
            except ValueError:
                return _mpi.MPI()

    property z:
        """Return the Z coordinate."""
        def __get__(self):
            try:
                return _mpi.from_mpi(&self._ctx.Z)
            except ValueError:
                return _mpi.MPI()

    def _tuple(self):
        return (self.x, self.y)

    def __str__(self):
        return self._tuple().__str__()

    def __eq__(self, other):
        if other == 0:
            return _pk.mbedtls_ecp_is_zero(&self._ctx) == 1
        elif type(other) is type(self):
            c_other = <ECPoint> other
            return _pk.mbedtls_ecp_point_cmp(&self._ctx, &c_other._ctx)
        elif isinstance(other, Sequence):
            return self._tuple() == other
        return NotImplemented

    def __len__(self):
        return self._tuple().__len__()

    def __getitem__(self, key):
        return self._tuple().__getitem__(key)

    def __contains__(self, value):
        return self._tuple().__contains__(value)

    def __iter__(self):
        return self._tuple().__iter__()

    def index(self, value):
        return self._tuple().index(value)

    def count(self, value):
        return self._tuple().count(value)

    def copy(self):
        """Return a copy of this point."""
        cdef ECPoint other = ECPoint()
        check_error(_pk.mbedtls_ecp_copy(&other._ctx, &self._ctx))
        return other


cdef class ECC(CipherBase):

    """Elliptic-curve cryptosystems.

    Args:
        (Curve, optional): A curve returned by `get_supported_curves()`.

    See Also:
        get_supported_curves()

    """
    def __init__(self, curve=None):
        super().__init__(b"EC")
        if curve is None:
            curve = get_supported_curves()[0]
        self.curve = curve

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        cdef const mbedtls_ecp_keypair* ecp = _pk.mbedtls_pk_ec(self._ctx)
        return _mpi.mbedtls_mpi_cmp_mpi(&ecp.d, &_mpi.MPI()._ctx) != 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        cdef mbedtls_ecp_keypair* ecp = _pk.mbedtls_pk_ec(self._ctx)
        return not _pk.mbedtls_ecp_is_zero(&ecp.Q)

    def generate(self):
        """Generate an EC keypair.

        Return:
            (bytes): The private key in DER format.

        """
        grp_id = curve_name_to_grp_id(self.curve)
        if grp_id is None:
            raise ValueError(self.curve)
        check_error(_pk.mbedtls_ecp_gen_key(
            grp_id, _pk.mbedtls_pk_ec(self._ctx),
            &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
        return self.export_key("DER")

    def _private_to_num(self):
        try:
            return _mpi.from_mpi(&_pk.mbedtls_pk_ec(self._ctx).d)
        except ValueError:
            return _mpi.MPI()

    def export_key(self, format="DER"):
        """Return the private key.

        If not key is present, return a falsy value.

        Args:
            format (str): One of "DER", "PEM", or "NUM".

        """
        if format == "NUM":
            return self._private_to_num()
        return super().export_key(format)

    def _public_to_point(self):
        point = ECPoint()
        _pk.mbedtls_ecp_copy(&point._ctx, &_pk.mbedtls_pk_ec(self._ctx).Q)
        return point

    def export_public_key(self, format="DER"):
        """Return the public key.

        If no key is present, return a falsy value.

        Args:
            format (str): One of "DER", "PEM", or "POINT".

        """
        if format == "POINT":
            return self._public_to_point()
        return super().export_public_key(format)

    def to_ECDH_server(self):
        """Return an ECDH server initialized with this context."""
        ecdh = ECDHServer(self.curve)
        check_error(_pk.mbedtls_ecdh_get_params(
            &ecdh._ctx, _pk.mbedtls_pk_ec(self._ctx), MBEDTLS_ECDH_OURS))
        return ecdh

    def to_ECDH_client(self):
        """Return an ECDH client initialized with this context."""
        ecdh = ECDHClient(self.curve)
        check_error(_pk.mbedtls_ecdh_get_params(
            &ecdh._ctx, _pk.mbedtls_pk_ec(self._ctx), MBEDTLS_ECDH_THEIRS))
        return ecdh


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
        check_error(_mpi.mbedtls_mpi_copy(
            &self._ctx.P, &_mpi.MPI(modulus)._ctx))
        check_error(_mpi.mbedtls_mpi_copy(
            &self._ctx.G, &_mpi.MPI(generator)._ctx))

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_dhm_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_dhm_free(&self._ctx)

    property key_size:
        """Return the size of the key, in bytes."""
        def __get__(self):
            return _mpi.mbedtls_mpi_size(&self._ctx.P)

    property modulus:
        """Return the prime modulus, P."""
        def __get__(self):
            return _mpi.from_mpi(&self._ctx.P)

    property generator:
        """Return the generator, G."""
        def __get__(self):
            return _mpi.from_mpi(&self._ctx.G)

    property _secret:
        """Return the secret (int)."""
        def __get__(self):
            return _mpi.from_mpi(&self._ctx.X)

    property shared_secret:
        """The shared secret (int).

        The shared secret is 0 if the TLS handshake is not finished.

        """
        def __get__(self):
            try:
                return _mpi.from_mpi(&self._ctx.K)
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
            check_error(mbedtls_dhm_calc_secret(
                &self._ctx, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE, &olen,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
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
            check_error(_pk.mbedtls_dhm_make_params(
                &self._ctx, self.key_size, &output[0], &olen,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return bytes(output[:olen])
        finally:
            free(output)

    def import_CKE(self, const unsigned char[:] buffer):
        """Read the ClientKeyExchange payload."""
        check_error(_pk.mbedtls_dhm_read_public(
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
            check_error(_pk.mbedtls_dhm_make_public(
                &self._ctx, self.key_size, &output[0], self.key_size,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            mpi = _mpi.from_mpi(&self._ctx.GX)
            return mpi.to_bytes(
                _mpi.mbedtls_mpi_size(&mpi._ctx), "big")
        finally:
            free(output)

    def import_SKE(self, const unsigned char[:] buffer):
        """Read the ServerKeyExchange payload."""
        cdef const unsigned char* first = &buffer[0]
        cdef const unsigned char* end = &buffer[-1] + 1
        check_error(_pk.mbedtls_dhm_read_params(
            &self._ctx, &first, end))


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
        self.curve = curve
        check_error(mbedtls_ecp_group_load(
            &self._ctx.grp, curve_name_to_grp_id(self.curve)))

    def __cinit__(self):
        """Initialize the context."""
        _pk.mbedtls_ecdh_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _pk.mbedtls_ecdh_free(&self._ctx)

    def _has_private(self):
        """Return `True` if the key contains a valid private half."""
        return _mpi.mbedtls_mpi_cmp_mpi(&self._ctx.d, &_mpi.MPI()._ctx) != 0

    def _has_public(self):
        """Return `True` if the key contains a valid public half."""
        return not _pk.mbedtls_ecp_is_zero(&self._ctx.Q)

    def _has_peers_public(self):
        """Return `True` if the peer's key is present."""
        return not _pk.mbedtls_ecp_is_zero(&self._ctx.Qp)

    def generate_secret(self):
        """Generate the shared secret."""
        cdef _mpi.MPI mpi = _mpi.MPI()
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            check_error(mbedtls_ecdh_calc_secret(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            _mpi.mbedtls_mpi_read_binary(&mpi._ctx, &output[0], olen)
            return mpi
        finally:
            free(output)

    property shared_secret:
        """The shared secret (int).

        The shared secret is 0 if the TLS handshake is not finished.

        """
        def __get__(self):
            try:
                return _mpi.from_mpi(&self._ctx.z)
            except ValueError:
                return _mpi.MPI()


cdef class ECDHServer(ECDHBase):

    """The server side of the ECDH key exchange.

    Args:
        (Curve, optional): A curve returned by `get_supported_curves()`.

    """
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
            check_error(_pk.mbedtls_ecdh_make_params(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return bytes(output[:olen])
        finally:
            free(output)

    def import_CKE(self, const unsigned char[:] buffer):
        """Read the ClientKeyExchange payload."""
        check_error(_pk.mbedtls_ecdh_read_public(
            &self._ctx, &buffer[0], buffer.size))


cdef class ECDHClient(ECDHBase):

    """The client side of the ephemeral ECDH key exchange.

    Args:
        (Curve, optional): A curve returned by `get_supported_curves()`.

    """
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
            check_error(_pk.mbedtls_ecdh_make_public(
                &self._ctx, &olen, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE,
                &_random.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return bytes(output[:olen])
        finally:
            free(output)

    def import_SKE(self, const unsigned char[:] buffer):
        """Read the ServerKeyExchange payload."""
        cdef const unsigned char* first = &buffer[0]
        cdef const unsigned char* end = &buffer[-1] + 1
        check_error(_pk.mbedtls_ecdh_read_params(
            &self._ctx, &first, end))
