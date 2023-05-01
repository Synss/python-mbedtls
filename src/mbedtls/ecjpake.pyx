# SPDX-License-Identifier: MIT

"""EC J-PAKE library.

The library handles EC J-PAKE key exchange.

"""


from libc.stdlib cimport free, malloc

cimport mbedtls._ecjpake as _ecjpake
cimport mbedtls._ecp as _ecp
cimport mbedtls._random as _rnd
cimport mbedtls.mpi as _mpi

import enum
from functools import partial

import mbedtls._random as _rnd
import mbedtls.exceptions as _exc
from mbedtls.hashlib import new as _new_hash

__all__ = ("get_supported_curves", "Curve", "ECJPAKE", "RoleType")


class RoleType(enum.Enum):
    SERVER = _ecjpake.MBEDTLS_ECJPAKE_SERVER
    CLIENT = _ecjpake.MBEDTLS_ECJPAKE_CLIENT


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


def get_supported_curves():
    """Return the list of supported curves in order of preference."""
    cdef const _ecp.mbedtls_ecp_curve_info* info = _ecp.mbedtls_ecp_curve_list()
    names, idx = [], 0
    while info[idx].name != NULL:
        if info[idx].name not in (Curve.CURVE25519.value, Curve.CURVE448.value):
            names.append(Curve(bytes(info[idx].name)))
        idx += 1
    print(names)
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


cdef class ECJPAKE:
    """Class for EC J-PAKE key exchange: client and server.

    Arguments:
        role (RoleType): The role to take, client or server.
        secret (bytes): A pre-shared secret (passphrase)
        digestmod (str, optional): The message digest algorithm type.
        curve (Curve, optional): A curve returned by `get_supported_curves()`.
    """
    cdef _ecjpake.mbedtls_ecjpake_context _ctx

    def __init__(self,
                 role,
                 const unsigned char[:] secret not None,
                 digestmod=None,
                 curve=None):
        if digestmod is None:
            digestmod = 'sha256'
        md_alg = _get_md_alg(digestmod)(secret)

        if curve is None:
            curve = get_supported_curves()[0]
        grp_id = curve_name_to_grp_id(Curve(curve))
        if  grp_id is None:
            raise ValueError(curve)

        _ecjpake.mbedtls_ecjpake_setup(
            &self._ctx,
            role,
            md_alg._type,
            grp_id,
            &secret[0],
            secret.size)

    def __cinit__(self):
        """Initialize the context."""
        _ecjpake.mbedtls_ecjpake_init(&self._ctx)

    def __dealloc__(self):
        """Free and clear the context."""
        _ecjpake.mbedtls_ecjpake_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def check_ready(self):
        """Check if ECJPAKE is ready for use.

        Return:
            true if the ECJPAKE is ready, false otherwise.
        """
        return _ecjpake.mbedtls_ecjpake_check(&self._ctx) == 0

    def write_round_one(self):
        """Generate and write the first round message.

        Return:
            bytes or None: The first round message or None.
        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecjpake.mbedtls_ecjpake_write_round_one(
                &self._ctx, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE, &olen,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)

    def read_round_one(self,
                       const unsigned char[:] message):
        """Read and process the first round message.

        Arguments:
            message (bytes): The first round message.
        """
        try:
            _exc.check_error(_ecjpake.mbedtls_ecjpake_read_round_one(
                &self._ctx, &message[0], message.size))
        finally:
            pass

    def write_round_two(self):
        """Generate and write the second round message.

        Return:
            bytes or None: The second round message or None.
        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecjpake.mbedtls_ecjpake_write_round_two(
                &self._ctx, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE, &olen,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)

    def read_round_two(self,
                       const unsigned char[:] message):
        """Read and process the second round message.

        Arguments:
            message (bytes): The second round message.
        """
        try:
            _exc.check_error(_ecjpake.mbedtls_ecjpake_read_round_two(
                &self._ctx, &message[0], message.size))
        finally:
            pass

    def derive_secret(self):
        """Derive the shared secret.

        Return:
            bytes or None: The shared secret.
        """
        cdef unsigned char* output = <unsigned char*>malloc(
            _mpi.MBEDTLS_MPI_MAX_SIZE * sizeof(unsigned char))
        cdef size_t olen = 0
        if not output:
            raise MemoryError()
        try:
            _exc.check_error(_ecjpake.mbedtls_ecjpake_derive_secret(
                &self._ctx, &output[0], _mpi.MBEDTLS_MPI_MAX_SIZE, &olen,
                &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return output[:olen]
        finally:
            free(output)
