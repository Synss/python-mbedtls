# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

cimport libc.stdio as c_stdio
from libc.stdlib cimport free, malloc

cimport mbedtls._debug as _debug
cimport mbedtls._random as _rnd
cimport mbedtls._timing as _timing
cimport mbedtls._tls as _tls
cimport mbedtls.pk as _pk
cimport mbedtls.x509 as _x509

import enum
from collections import abc
from functools import partial
from itertools import tee
from pathlib import Path

import certifi
import cython

import mbedtls._random as _rnd
import mbedtls._ringbuf as _rb
import mbedtls.exceptions as _exc
import mbedtls.pk as _pk
from mbedtls._tlsi import (
    DTLSConfiguration,
    DTLSVersion,
    MaxFragmentLength,
    NextProtocol,
    TLSConfiguration,
    TLSVersion,
)


cdef _rnd.Random __rng = _rnd.default_rng()


class Transport(enum.Enum):
    STREAM = _tls.MBEDTLS_SSL_TRANSPORT_STREAM
    DATAGRAM = _tls.MBEDTLS_SSL_TRANSPORT_DATAGRAM


cdef class _PSKSToreProxy:
    def __init__(self, psk_store):
        if not isinstance(psk_store, abc.Mapping):
            raise TypeError("Mapping expected but got %r instead" % psk_store)
        self._mapping = psk_store

    def unwrap(self):
        return self._mapping

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self._mapping)

    def __str__(self):
        return self._mapping.__str__()

    def __getitem__(self, key):
        return self._mapping.__getitem__(key)

    def __iter__(self):
        return self._mapping.__iter__()

    def __len__(self):
        return self._mapping.__len__()


# Python 2.7: `register()` can be used as a decorator from 3.3.
abc.Mapping.register(_PSKSToreProxy)


@cython.boundscheck(False)
cdef void _my_debug(void *ctx, int level,
                    const char *file, int line, const char *str) noexcept nogil:
    c_stdio.fprintf(<c_stdio.FILE *> ctx, "%s:%04d: %s", file, line, str)
    c_stdio.fflush(<c_stdio.FILE *> ctx)


def _enable_debug_output(_BaseContext context):
    _tls.mbedtls_ssl_conf_dbg(&context._conf._ctx, _my_debug, c_stdio.stdout)


@cython.boundscheck(False)
cdef int buffer_write(void *ctx, const unsigned char *buf, size_t len) noexcept nogil:
    """"Write buffer to output buffer."""
    c_buf = <_tls._C_Buffers *> ctx
    if len == 0:
        return _tls.MBEDTLS_ERR_SSL_BAD_INPUT_DATA
    if _rb.c_len(c_buf.out_ctx) == _rb.c_capacity(c_buf.out_ctx):
        return _tls.MBEDTLS_ERR_SSL_WANT_READ
    cdef size_t writelen = min(
        len, _rb.c_capacity(c_buf.out_ctx) - _rb.c_len(c_buf.out_ctx)
    )
    return _rb.c_write(c_buf.out_ctx, buf, writelen)


@cython.boundscheck(False)
cdef int buffer_read(void *ctx, unsigned char *buf, const size_t len) noexcept nogil:
    """Read from input buffer."""
    c_buf = <_tls._C_Buffers *> ctx
    if _rb.c_len(c_buf.in_ctx) == 0:
        return _tls.MBEDTLS_ERR_SSL_WANT_READ
    return _rb.c_readinto(c_buf.in_ctx, buf, len)


@cython.boundscheck(False)
cdef int _psk_cb(
    void *parameter,
    _tls.mbedtls_ssl_context *ctx,
    const unsigned char *c_identity,
    size_t c_identity_len
) noexcept nogil:
    """Wrapper for the PSK callback."""
    # If a valid PSK identity is found, call `mbedtls_ssl_set_hs_psk()` and
    # return 0. Otherwise, return 1.
    with gil:
        store = <_tls._PSKSToreProxy> parameter
        identity = c_identity[:c_identity_len]
        try:
            psk = store[identity.decode("utf8")]
            _tls.mbedtls_ssl_set_hs_psk(ctx, psk, len(psk))
            return 0
        except Exception:
            return 1


def _set_debug_level(int level):
    """Set debug level for logging."""
    _debug.mbedtls_debug_set_threshold(level)


def __get_ciphersuite_name(ciphersuite_id):
    """Return a string containing the ciphersuite name.

    Args:
        ciphersuite_id: The ID of the ciphersuite.

    """
    return _tls.mbedtls_ssl_get_ciphersuite_name(
        ciphersuite_id).decode("ascii")


def __get_ciphersuite_id(name):
    """Return the ciphersuite name from ID.

    Args:
        name (str): The name of the ciphersuite.

    """
    cdef char[:] c_name = bytearray(name.encode("ascii"))
    return _tls.mbedtls_ssl_get_ciphersuite_id(&c_name[0])


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def ciphers_available():
    """Return the list of ciphersuites supported by the SSL/TLS module.

    See Also:
        - hashlib.algorithms_available
        - hmac.algorithms_available

    """
    cdef const int* ids = _tls.mbedtls_ssl_list_ciphersuites()
    cdef size_t n = 0
    ciphersuites = []
    while ids[n]:
        ciphersuites.append(__get_ciphersuite_name(ids[n]))
        n += 1
    return tuple(ciphersuites)


__TLSVersion = {
    (0x02, 0x00): TLSVersion.SSLv2,
    (0x03, 0x00): TLSVersion.SSLv3,
    (0x03, 0x01): TLSVersion.TLSv1,
    (0x03, 0x02): TLSVersion.TLSv1_1,
    (0x03, 0x03): TLSVersion.TLSv1_2,
    (0x03, 0x04): TLSVersion.TLSv1_3,
}

__DTLSVersion = {
    (0x03, 0x02): DTLSVersion.DTLSv1_0,
    (0x03, 0x03): DTLSVersion.DTLSv1_2,
}


def __to_version(maj_min_version, mapping):
    try:
        return mapping[maj_min_version]
    except KeyError as exc:
        raise ValueError(f"0x{maj_min_version[0]:02x}{maj_min_version[1]:02x}")


def __from_version(version, mapping):
    if not isinstance(version, (TLSVersion, DTLSVersion)):
        raise TypeError(version)
    try:
        return {v: k for k, v in mapping.items()}[version]
    except KeyError as exc:
        raise ValueError(str(version)) from exc


_tls_to_version = partial(__to_version, mapping=__TLSVersion)
_dtls_to_version = partial(__to_version, mapping=__DTLSVersion)
_tls_from_version = partial(__from_version, mapping=__TLSVersion)
_dtls_from_version = partial(__from_version, mapping=__DTLSVersion)


_SUPPORTED_TLS_VERSION = [
    TLSVersion.TLSv1,
    TLSVersion.TLSv1_1,
    TLSVersion.TLSv1_2,
    # TLSVersion.TLSv1_3,  # experimental in 2.28.0
]


_SUPPORTED_DTLS_VERSION = [
    DTLSVersion.DTLSv1_0,
    DTLSVersion.DTLSv1_2,
]


def _check_tls_version(version):
    if not isinstance(version, TLSVersion):
        raise TypeError(version)
    if version is TLSVersion.MINIMUM_SUPPORTED:
        version = _SUPPORTED_TLS_VERSION[0]
    if version is TLSVersion.MAXIMUM_SUPPORTED:
        version = _SUPPORTED_TLS_VERSION[-1]
    if version not in _SUPPORTED_TLS_VERSION:
        raise ValueError(version)
    return version


def _check_dtls_version(version):
    if not isinstance(version, DTLSVersion):
        raise TypeError(version)
    if version is DTLSVersion.MINIMUM_SUPPORTED:
        version = _SUPPORTED_DTLS_VERSION[0]
    if version is DTLSVersion.MAXIMUM_SUPPORTED:
        version = _SUPPORTED_DTLS_VERSION[-1]
    if version not in _SUPPORTED_DTLS_VERSION:
        raise ValueError(version)
    return version


class HandshakeStep(enum.Enum):
    HELLO_REQUEST = _tls.MBEDTLS_SSL_HELLO_REQUEST
    CLIENT_HELLO = _tls.MBEDTLS_SSL_CLIENT_HELLO
    SERVER_HELLO = _tls.MBEDTLS_SSL_SERVER_HELLO
    SERVER_CERTIFICATE = _tls.MBEDTLS_SSL_SERVER_CERTIFICATE
    SERVER_KEY_EXCHANGE = _tls.MBEDTLS_SSL_SERVER_KEY_EXCHANGE
    CERTIFICATE_REQUEST = _tls.MBEDTLS_SSL_CERTIFICATE_REQUEST
    SERVER_HELLO_DONE = _tls.MBEDTLS_SSL_SERVER_HELLO_DONE
    CLIENT_CERTIFICATE = _tls.MBEDTLS_SSL_CLIENT_CERTIFICATE
    CLIENT_KEY_EXCHANGE = _tls.MBEDTLS_SSL_CLIENT_KEY_EXCHANGE
    CERTIFICATE_VERIFY = _tls.MBEDTLS_SSL_CERTIFICATE_VERIFY
    CLIENT_CHANGE_CIPHER_SPEC = _tls.MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC
    CLIENT_FINISHED = _tls.MBEDTLS_SSL_CLIENT_FINISHED
    SERVER_CHANGE_CIPHER_SPEC = _tls.MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC
    SERVER_FINISHED = _tls.MBEDTLS_SSL_SERVER_FINISHED
    FLUSH_BUFFERS = _tls.MBEDTLS_SSL_FLUSH_BUFFERS
    HANDSHAKE_WRAPUP = _tls.MBEDTLS_SSL_HANDSHAKE_WRAPUP
    HANDSHAKE_OVER = _tls.MBEDTLS_SSL_HANDSHAKE_OVER
    SERVER_NEW_SESSION_TICKET = _tls.MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET
    SERVER_HELLO_VERIFY_REQUEST_SENT = (
        _tls.MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT
    )


PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


class WantWriteError(_exc.TLSError):
    pass


class WantReadError(_exc.TLSError):
    pass


class RaggedEOF(_exc.TLSError):
    pass


class HelloVerifyRequest(_exc.TLSError):
    pass


class TrustStore(abc.Sequence):
    def __init__(self, db=None):
        if db is None:
            db = []
        self._db = list(db)

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self._db)

    @classmethod
    def system(cls):
        return cls.from_pem_file(certifi.where())

    @classmethod
    def from_pem_file(cls, path):
        self = cls()
        with Path(path).open() as cacert:
            pem = None
            for line in cacert.readlines():
                if line.startswith(PEM_HEADER):
                    pem = []
                elif line.strip().endswith(PEM_FOOTER):
                    self.add(_x509.CRT.from_PEM("".join(pem)))
                    pem = None
                elif pem is not None:
                    pem.append(line)
        return self

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._db == other._db

    def __bool__(self):
        return bool(self._db)

    def __len__(self):
        return len(self._db)

    def __getitem__(self, item):
        if isinstance(item, slice):
            return TrustStore(self._db[slice])
        return self._db[item]

    def add(self, _x509.CRT crt):
        if crt in self:
            return
        cdef _x509.CRT c_crt
        if self._db:
            c_crt = self._db[-1]
            c_crt.set_next(crt)
        self._db.append(crt)


class Purpose(enum.IntEnum):
    SERVER_AUTH = _tls.MBEDTLS_SSL_IS_SERVER
    CLIENT_AUTH = _tls.MBEDTLS_SSL_IS_CLIENT


_DEFAULT_VALUE = object()


cdef class _DTLSCookie:
    """DTLS cookie."""

    def __cinit__(self):
        _tls.mbedtls_ssl_cookie_init(&self._ctx)

    def __dealloc__(self):
        _tls.mbedtls_ssl_cookie_free(&self._ctx)

    @property
    def timeout(self):
        return self._ctx.timeout

    @timeout.setter
    def timeout(self, unsigned long timeout):
        _tls.mbedtls_ssl_cookie_set_timeout(&self._ctx, timeout)

    def generate(self):
        """Generate keys."""
        _tls.mbedtls_ssl_cookie_setup(
            &self._ctx, _rnd.mbedtls_ctr_drbg_random, &__rng._ctx)


cdef class MbedTLSConfiguration:

    """(D)TLS configuration."""

    def __init__(
        self,
        validate_certificates,
        certificate_chain,
        ciphers,
        inner_protocols,
        lowest_supported_version,
        highest_supported_version,
        trust_store,
        max_fragmentation_length,
        anti_replay,
        # badmac_limit
        handshake_timeout_min,
        handshake_timeout_max,
        sni_callback,
        pre_shared_key,
        pre_shared_key_store,
        _transport,
    ):
        assert isinstance(_transport, Transport)
        self._max_fragmentation_length = max_fragmentation_length
        _exc.check_error(_tls.mbedtls_ssl_config_defaults(
            &self._ctx,
            endpoint=0,  # server / client is not known here...
            transport=_transport.value,
            preset=_tls.MBEDTLS_SSL_PRESET_DEFAULT))
        self._set_validate_certificates(validate_certificates)
        self._set_certificate_chain(certificate_chain)
        self._set_ciphers(ciphers)
        self._set_inner_protocols(inner_protocols)
        self._set_lowest_supported_version(lowest_supported_version)
        self._set_highest_supported_version(highest_supported_version)
        self._set_trust_store(trust_store)
        self._set_max_fragmentation_length(max_fragmentation_length)
        self._set_anti_replay(anti_replay)
        self._set_handshake_timeout(
            handshake_timeout_min, handshake_timeout_max
        )
        self._set_sni_callback(sni_callback)
        self._set_pre_shared_key(pre_shared_key)
        self._set_pre_shared_key_store(pre_shared_key_store)

        # Set random engine.
        _tls.mbedtls_ssl_conf_rng(
            &self._ctx, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx)

        # Disable renegotiation.
        _tls.mbedtls_ssl_conf_renegotiation(&self._ctx, 0)

        # For security reasons, we do not make cookie optional here.
        cdef _tls._DTLSCookie cookie = _tls._DTLSCookie()
        cookie.generate()
        self._set_cookie(cookie)

    def __cinit__(self):
        _tls.mbedtls_ssl_config_init(&self._ctx)

        cdef Py_ssize_t ciphers_sz = len(ciphers_available()) + 1
        self._ciphers = <int *>malloc(ciphers_sz * sizeof(int))
        if not self._ciphers:
            raise MemoryError()

        cdef Py_ssize_t idx = 0
        for idx in range(ciphers_sz):
            self._ciphers[idx] = 0

        cdef Py_ssize_t protos_sz = len(NextProtocol) + 1
        self._protos = <const char **>malloc(protos_sz * sizeof(char *))
        if not self._protos:
            raise MemoryError()

        for idx in range(protos_sz):
            self._protos[idx] = NULL

    def __dealloc__(self):
        _tls.mbedtls_ssl_config_free(&self._ctx)
        free(self._ciphers)
        free(self._protos)

    def __reduce__(self):
        return (
            type(self),
            (
                self.validate_certificates,
                self.certificate_chain,
                self.ciphers,
                self.inner_protocols,
                self.lowest_supported_version,
                self.highest_supported_version,
                self.trust_store,
                self.max_fragmentation_length,
                self.anti_replay,
                self.handshake_timeout_min,
                self.handshake_timeout_max,
                self.sni_callback,
                self.pre_shared_key,
                self.pre_shared_key_store,
                self._transport,
            ),
        )

    @property
    def _transport(self):
        return Transport(self._ctx.transport)

    cdef _set_validate_certificates(self, validate):
        """Set the certificate verification mode.

        """  # PEP 543
        if validate is None:
            return
        _tls.mbedtls_ssl_conf_authmode(
            &self._ctx,
            _tls.MBEDTLS_SSL_VERIFY_OPTIONAL if validate is False else
            _tls.MBEDTLS_SSL_VERIFY_REQUIRED)

    @property
    def validate_certificates(self):
        return self._ctx.authmode == _tls.MBEDTLS_SSL_VERIFY_REQUIRED

    cdef _set_certificate_chain(self, chain):
        """The certificate, intermediate certificate, and
        the corresponding private key for the leaf certificate.

        Args:
            chain (Tuple[Tuple[Certificate], PrivateKey]):
                The certificate chain.

        """
        # PEP 543
        if not chain:
            return
        self._chain = chain
        certs, pk_key = chain
        if not certs or not pk_key:
            return
        cdef _x509.CRT c_crt, c_crt_next
        for c_crt, c_crt_next in pairwise(certs):
            c_crt.set_next(c_crt_next)
        c_crt = certs[0]
        c_pk_key = <_pk.CipherBase?> pk_key
        _exc.check_error(_tls.mbedtls_ssl_conf_own_cert(
            &self._ctx, &c_crt._ctx, &c_pk_key._ctx))

    @property
    def certificate_chain(self):
        key_cert = self._ctx.key_cert
        if key_cert is NULL:
            return None
        chain = []
        cdef _x509.mbedtls_x509_crt *c_ctx = key_cert.cert
        while c_ctx is not NULL:
            chain.append(_x509.CRT.from_DER(c_ctx.raw.p[0:c_ctx.raw.len]))
            c_ctx = c_ctx.next
        cdef unsigned char[:] buf = bytearray(_pk.PRV_DER_MAX_BYTES)
        olen = _exc.check_error(
            _pk.mbedtls_pk_write_key_der(key_cert.key, &buf[0], buf.size))
        der = buf[buf.size - olen:buf.size]
        if _pk.mbedtls_pk_can_do(key_cert.key, _pk.MBEDTLS_PK_RSA) == 0:
            return tuple(chain), _pk.ECC.from_DER(der)
        return tuple(chain), _pk.RSA.from_DER(der)

    cdef _set_ciphers(self, ciphers):
        """The available ciphers for the TLS connections.

        Args:
            ciphers (Tuple[Union[CipherSuite, int]]): The ciphers.

        """
        # PEP 543
        if ciphers is None:
            return
        if not frozenset(ciphers).issubset(ciphers_available()):
            raise NotImplementedError("unsupported ciphers")
        cdef Py_ssize_t idx = 0
        self._ciphers[idx] = 0
        for idx, cipher in enumerate(ciphers):
            if not isinstance(cipher, int):
                cipher = __get_ciphersuite_id(cipher)
            self._ciphers[idx] = cipher
        self._ciphers[idx + 1] = 0
        _tls.mbedtls_ssl_conf_ciphersuites(&self._ctx, self._ciphers)

    @property
    def ciphers(self):
        ciphers = []
        cdef int cipher_id
        cdef Py_ssize_t idx
        for idx in range(len(ciphers_available())):
            cipher_id = self._ciphers[idx]
            if cipher_id == 0:
                break
            ciphers.append(__get_ciphersuite_name(cipher_id))
        return tuple(ciphers)

    cdef _set_inner_protocols(self, protocols):
        """

        Args:
            protocols ([Tuple[Union[NextProtocol, bytes]]]): Protocols
                that connections created with this configuration should
                advertise as supported during the TLS handshake. These may
                be advertised using either or both of ALPN or NPN. This
                list of protocols should be ordered by preference.

        """
        # PEP 543
        if protocols is None:
            return
        if len(protocols) > len(NextProtocol):
            raise ValueError("invalid protocols")

        cdef Py_ssize_t idx = 0
        for idx, proto in enumerate(protocols):
            if not isinstance(proto, bytes):
                proto = proto.value
            self._protos[idx] = proto
        self._protos[idx + 1] = NULL

        _exc.check_error(_tls.mbedtls_ssl_conf_alpn_protocols(
            &self._ctx, self._protos))

    @property
    def inner_protocols(self):
        protos = []
        cdef const char* proto
        for idx in range(len(NextProtocol)):
            proto = self._protos[idx]
            if proto is NULL:
                break
            protos.append(NextProtocol(proto))
        return tuple(protos)

    cdef _set_lowest_supported_version(self, version):
        """The minimum version of TLS that should be allowed.

        Args:
            version (TLSVersion, or DTLSVersion): The minimum version.

        """  # PEP 543
        if self._transport is Transport.STREAM:
            version = _check_tls_version(
                version
                if version is not None
                else TLSVersion.MINIMUM_SUPPORTED
            )
        if self._transport is Transport.DATAGRAM:
            version = _check_dtls_version(
                version
                if version is not None
                else DTLSVersion.MINIMUM_SUPPORTED
            )
        try:
            major, minor = {
                TLSVersion: _tls_from_version,
                DTLSVersion: _dtls_from_version,
            }[type(version)](version)
        except KeyError as exc:
            raise TypeError(version) from exc

        _tls.mbedtls_ssl_conf_min_version(&self._ctx, major, minor)

    @property
    def lowest_supported_version(self):
        maj_min_version = self._ctx.min_major_ver, self._ctx.min_minor_ver
        if self._transport is Transport.STREAM:
            return _tls_to_version(maj_min_version)
        if self._transport is Transport.DATAGRAM:
            return _dtls_to_version(maj_min_version)
        assert 0, "unreachable"

    cdef _set_highest_supported_version(self, version):
        """The maximum version of TLS that should be allowed.

        Args:
            version (TLSVersion, or DTLSVersion): The maximum version.

        """  # PEP 543
        if self._transport is Transport.STREAM:
            version = _check_tls_version(
                version
                if version is not None
                else TLSVersion.MAXIMUM_SUPPORTED
            )
        if self._transport is Transport.DATAGRAM:
            version = _check_dtls_version(
                version
                if version is not None
                else DTLSVersion.MAXIMUM_SUPPORTED
            )
        try:
            major, minor = {
                TLSVersion: _tls_from_version,
                DTLSVersion: _dtls_from_version,
            }[type(version)](version)
        except KeyError as exc:
            raise TypeError(version) from exc

        _tls.mbedtls_ssl_conf_max_version(&self._ctx, major, minor)

    @property
    def highest_supported_version(self):
        maj_min_version = self._ctx.max_major_ver, self._ctx.max_minor_ver
        if self._transport is Transport.STREAM:
            return _tls_to_version(maj_min_version)
        if self._transport is Transport.DATAGRAM:
            return _dtls_to_version(maj_min_version)
        assert 0, "unreachable"

    cdef _set_trust_store(self, store):
        """The trust store that connections will use.

        Args:
            store (TrustStore): The trust store.

        """
        # PEP 543
        if not store:
            return
        cdef _x509.CRT crt = TrustStore(store)[0]
        mbedtls_ssl_conf_ca_chain(&self._ctx, &crt._ctx, NULL)

    @property
    def trust_store(self):
        store = TrustStore()
        if self._ctx.ca_chain is NULL:
            return store

        cdef _x509.mbedtls_x509_crt *c_ctx = self._ctx.ca_chain
        while c_ctx is not NULL:
            store.add(_x509.CRT.from_DER(c_ctx.raw.p[0:c_ctx.raw.len]))
            c_ctx = c_ctx.next
        return store

    cdef _set_max_fragmentation_length(self, mfl):
        if mfl is None:
            return

        if not isinstance(mfl, MaxFragmentLength):
            raise TypeError(mfl)

        try:
            _exc.check_error(
                _tls.mbedtls_ssl_conf_max_frag_len(&self._ctx, mfl.value)
            )
        except _exc.TLSError as exc:
            raise ValueError(mfl) from exc

    @property
    def max_fragmentation_length(self):
        # No accessor in backend.
        return self._max_fragmentation_length

    cdef _set_anti_replay(self, anti_replay):
        """Set anti replay."""
        if anti_replay is None:
            return
        if self._transport is Transport.STREAM:
            # not available with TLS
            raise ValueError(anti_replay)
        _tls.mbedtls_ssl_conf_dtls_anti_replay(
            &self._ctx,
            _tls.MBEDTLS_SSL_ANTI_REPLAY_ENABLED
            if anti_replay else
            _tls.MBEDTLS_SSL_ANTI_REPLAY_DISABLED)

    @property
    def anti_replay(self):
        if self._transport is Transport.STREAM:
            return None

        cdef unsigned int enabled = _tls.MBEDTLS_SSL_ANTI_REPLAY_ENABLED
        return True if self._ctx.anti_replay == enabled else False

    cdef _set_handshake_timeout(self, minimum, maximum):
        """Set DTLS handshake timeout.

        Args:
            minimum (float, optional): minimum timeout in seconds.
            maximum (float, optional): maximum timeout in seconds.

        """
        if minimum is None and maximum is None:
            return
        if self._transport is Transport.STREAM:
            # not available with TLS
            raise ValueError((minimum, maximum))

        def validate(extremum, *, default: float) -> float:
            if extremum is None:
                return default
            if extremum < 0.0:
                raise ValueError(extremum)
            return extremum

        _tls.mbedtls_ssl_conf_handshake_timeout(
            &self._ctx,
            int(1000.0 * validate(minimum, default=1.0)),
            int(1000.0 * validate(maximum, default=60.0)),
        )

    @property
    def handshake_timeout_min(self):
        """Min handshake timeout in seconds (default 1.0)."""
        if self._transport is Transport.STREAM:
            return None

        return float(self._ctx.hs_timeout_min) / 1000.0

    @property
    def handshake_timeout_max(self):
        """Max handshake timeout in seconds (default 60.0)."""
        if self._transport is Transport.STREAM:
            return None

        return float(self._ctx.hs_timeout_max) / 1000.0

    cdef _set_sni_callback(self, callback):
        # PEP 543, optional, server-side only
        if callback is None:
            return
        # mbedtls_ssl_conf_sni
        raise NotImplementedError

    @property
    def sni_callback(self):
        return None

    cdef _set_pre_shared_key(self, psk):
        """Set a pre shared key (PSK) for the client.

        Args:
            psk ([Tuple[unicode, bytes]]): A tuple with the key and the exected
                identity name.

        """
        if psk is None:
            return
        try:
            identity, key = psk
        except ValueError:
            raise TypeError("expected a tuple (name, key)")
        c_identity = identity.encode("utf8")
        _exc.check_error(_tls.mbedtls_ssl_conf_psk(
            &self._ctx,
            key, len(key),
            c_identity, len(c_identity)))

    @property
    def pre_shared_key(self):
        if self._ctx.psk == NULL or self._ctx.psk_identity == NULL:
            return None
        key = self._ctx.psk[:self._ctx.psk_len]
        c_identity = self._ctx.psk_identity[:self._ctx.psk_identity_len]
        identity = c_identity.decode("utf8")
        return (identity, key)

    cdef _set_pre_shared_key_store(self, psk_store):
        # server-side
        if psk_store is None:
            return
        self._store = _PSKSToreProxy(psk_store)  # ownership
        _tls.mbedtls_ssl_conf_psk_cb(&self._ctx, _psk_cb, <void *> self._store)

    @property
    def pre_shared_key_store(self):
        if self._ctx.p_psk == NULL:
            return None
        psk_store = <_tls._PSKSToreProxy> self._ctx.p_psk
        return psk_store.unwrap()

    cdef _set_cookie(self, _tls._DTLSCookie cookie):
        """Register callbacks for DTLS cookies (server only)."""
        self._cookie = cookie
        if cookie is None:
            _tls.mbedtls_ssl_conf_dtls_cookies(
                &self._ctx,
                NULL,
                NULL,
                NULL,
            )
        else:
            _tls.mbedtls_ssl_conf_dtls_cookies(
                &self._ctx,
                _tls.mbedtls_ssl_cookie_write,
                _tls.mbedtls_ssl_cookie_check,
                &self._cookie._ctx,
            )


DEFAULT_CIPHER_LIST = None


cdef class TLSSession:
    def __cinit__(self):
        """Initialize SSL session structure."""
        _tls.mbedtls_ssl_session_init(&self._ctx)

    def __dealloc__(self):
        """Free referenced items in an SSL session."""
        _tls.mbedtls_ssl_session_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __repr__(self):
        return "%s()" % type(self).__name__


cdef class _BaseContext:
    # _pep543._BaseContext
    """Context base class."""

    def __init__(self, configuration not None):
        if isinstance(configuration, TLSConfiguration):
            self._conf = MbedTLSConfiguration(
                validate_certificates=configuration.validate_certificates,
                certificate_chain=configuration.certificate_chain,
                ciphers=configuration.ciphers,
                inner_protocols=configuration.inner_protocols,
                lowest_supported_version=(
                    configuration.lowest_supported_version
                ),
                highest_supported_version=(
                    configuration.highest_supported_version
                ),
                trust_store=configuration.trust_store,
                max_fragmentation_length=configuration.max_fragmentation_length,
                anti_replay=None,
                handshake_timeout_min=None,
                handshake_timeout_max=None,
                sni_callback=configuration.sni_callback,
                pre_shared_key=configuration.pre_shared_key,
                pre_shared_key_store=configuration.pre_shared_key_store,
                _transport=Transport.STREAM,
            )
        elif isinstance(configuration, DTLSConfiguration):
            self._conf = MbedTLSConfiguration(
                validate_certificates=configuration.validate_certificates,
                certificate_chain=configuration.certificate_chain,
                ciphers=configuration.ciphers,
                inner_protocols=configuration.inner_protocols,
                lowest_supported_version=(
                    configuration.lowest_supported_version
                ),
                highest_supported_version=(
                    configuration.highest_supported_version
                ),
                trust_store=configuration.trust_store,
                max_fragmentation_length=configuration.max_fragmentation_length,
                anti_replay=configuration.anti_replay,
                handshake_timeout_min=configuration.handshake_timeout_min,
                handshake_timeout_max=configuration.handshake_timeout_max,
                sni_callback=configuration.sni_callback,
                pre_shared_key=configuration.pre_shared_key,
                pre_shared_key_store=configuration.pre_shared_key_store,
                _transport=Transport.DATAGRAM,
            )
        else:
            # Setting `_conf` is required for delocate on macOS.
            self._conf = None
            raise TypeError(configuration)

        _tls.mbedtls_ssl_conf_endpoint(
            &self._conf._ctx,
            {
                Purpose.CLIENT_AUTH: _tls.MBEDTLS_SSL_IS_CLIENT,
                Purpose.SERVER_AUTH: _tls.MBEDTLS_SSL_IS_SERVER,
            }[self._purpose])

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        if not type(self) is type(other):
            return False
        return self.configuration == other.configuration

    @property
    def configuration(self):
        if self._conf._transport is Transport.STREAM:
            return TLSConfiguration(
                validate_certificates=self._conf.validate_certificates,
                certificate_chain=self._conf.certificate_chain,
                ciphers=self._conf.ciphers,
                inner_protocols=self._conf.inner_protocols,
                lowest_supported_version=self._conf.lowest_supported_version,
                highest_supported_version=self._conf.highest_supported_version,
                trust_store=self._conf.trust_store,
                max_fragmentation_length=self._conf.max_fragmentation_length,
                sni_callback=self._conf.sni_callback,
                pre_shared_key=self._conf.pre_shared_key,
                pre_shared_key_store=self._conf.pre_shared_key_store,
            )
        assert self._conf._transport is Transport.DATAGRAM
        return DTLSConfiguration(
            validate_certificates=self._conf.validate_certificates,
            certificate_chain=self._conf.certificate_chain,
            ciphers=self._conf.ciphers,
            inner_protocols=self._conf.inner_protocols,
            lowest_supported_version=self._conf.lowest_supported_version,
            highest_supported_version=self._conf.highest_supported_version,
            trust_store=self._conf.trust_store,
            max_fragmentation_length=self._conf.max_fragmentation_length,
            anti_replay=self._conf.anti_replay,
            handshake_timeout_min=self._conf.handshake_timeout_min,
            handshake_timeout_max=self._conf.handshake_timeout_max,
            sni_callback=self._conf.sni_callback,
            pre_shared_key=self._conf.pre_shared_key,
            pre_shared_key_store=self._conf.pre_shared_key_store,
        )

    @property
    def _purpose(self) -> Purpose:
        raise NotImplementedError


TLS_BUFFER_CAPACITY = 2 << 14
# 32K (MBEDTLS_SSL_DTLS_MAX_BUFFERING)


cdef class MbedTLSBuffer:
    def __init__(self, _BaseContext context, server_hostname=None):
        self._context = context
        _exc.check_error(
            _tls.mbedtls_ssl_setup(&self._ctx, &self._context._conf._ctx)
        )
        self._c_output_buffer = _rb.RingBuffer(TLS_BUFFER_CAPACITY)
        self._c_input_buffer = _rb.RingBuffer(TLS_BUFFER_CAPACITY)
        self._c_buffers = _tls._C_Buffers(
            &self._c_output_buffer._ctx,
            &self._c_input_buffer._ctx
        )
        self._reset()
        _tls.mbedtls_ssl_set_bio(
            &self._ctx,
            &self._c_buffers,
            buffer_write,
            buffer_read,
            NULL
        )
        self._set_hostname(server_hostname)

    def __cinit__(self):
        """Initialize an `ssl_context`."""
        _tls.mbedtls_ssl_init(&self._ctx)
        _tls.mbedtls_ssl_set_timer_cb(
            &self._ctx,
            &self._timer,
            _timing.mbedtls_timing_set_delay,
            _timing.mbedtls_timing_get_delay)

    def __dealloc__(self):
        """Free and clear the internal structures of ctx."""
        _tls.mbedtls_ssl_free(&self._ctx)

    def __getstate__(self):
        cdef size_t olen = 0
        ret = mbedtls_ssl_context_save(&self._ctx, NULL, 0, &olen)
        if ret != -0x6A00 or olen == 0:
            # 0x6A00: MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL
            raise TypeError(
                f"cannot pickle {self.__class__.__name__!r} object {hex(ret)}"
            )
        cdef unsigned char *c_buf = <unsigned char *> malloc(olen)
        if not c_buf:
            raise MemoryError()
        try:
            if mbedtls_ssl_context_save(&self._ctx, c_buf, olen, &olen) != 0:
                raise TypeError(
                    f"cannot pickle {self.__class__.__name__!r} object"
                )
            return {
                "connection": c_buf[:olen],
                "context": self.context,
                "server_hostname": self._server_hostname,
            }
        finally:
            free(c_buf)

    def __setstate__(self, state):
        self.__init__(state["context"], state["server_hostname"])
        cdef const unsigned char[:] buf = state["connection"]
        ret = mbedtls_ssl_context_load(&self._ctx, &buf[0], buf.size)
        if ret != 0:
            self._reset()
            raise TypeError(
                f"cannot unpickle {self.__class__.__name__!r} object"
            )

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.context)

    @property
    def _input_buffer(self):
        return self._c_input_buffer

    @property
    def _output_buffer(self):
        return self._c_output_buffer

    @property
    def context(self):
        return self._context

    @property
    def _verified(self):
        return _tls.mbedtls_ssl_get_verify_result(&self._ctx) == 0

    @property
    def _server_hostname(self):
        # Client side
        if self._ctx.hostname is NULL:
            return None
        return (<bytes> self._ctx.hostname).decode("utf8")

    def _set_hostname(self, hostname):
        """Set the hostname to check against the received server."""
        if hostname is None:
            return
        # Note: `ssl_set_hostname()` makes a copy so it is safe
        #       to call with the temporary `hostname_`.
        hostname_ = hostname.encode("utf8")
        cdef const char* c_hostname = hostname_
        _exc.check_error(_tls.mbedtls_ssl_set_hostname(&self._ctx, c_hostname))

    @property
    def _cookieparam(self):
        """Client ID for the HelloVerifyRequest.

        Note:
            Server-side, DTLS only.

        """
        client_id = bytes(self._ctx.cli_id[0:self._ctx.cli_id_len])
        return client_id if client_id else None

    def setcookieparam(self, const unsigned char[:] info not None):
        if info.size == 0:
            info = b"\0"
        _tls.mbedtls_ssl_set_client_transport_id(
            &self._ctx,
            &info[0],
            info.size,
        )

    def setmtu(self, mtu):
        """Set Maxiumum Transport Unit (MTU) for DTLS.

        Set to zero to unset.

        Raises:
            OverflowError: If value cannot be converted to UInt16.

        """
        # DTLS
        if not isinstance(mtu, int):
            raise TypeError(mtu)
        _tls.mbedtls_ssl_set_mtu(&self._ctx, mtu)

    def _reset(self):
        _exc.check_error(_tls.mbedtls_ssl_session_reset(&self._ctx))

    def shutdown(self):
        try:
            _exc.check_error(_tls.mbedtls_ssl_close_notify(&self._ctx))
        except (WantReadError, WantWriteError):
            raise
        except _exc.TLSError:
            # No error handling:  The connection may be closed already.
            self._reset()

    def read(self, amt):
        # PEP 543
        if amt <= 0:
            return b""
        buffer = bytearray(amt)
        view = memoryview(buffer)
        nread = 0
        while nread != amt and not self._input_buffer.empty():
            nread += self.readinto(view[nread:], amt - nread)
        return bytes(buffer[:nread])

    def readinto(self, unsigned char[:] buffer not None, size_t amt):
        if buffer.size == 0:
            return 0
        if amt <= 0:
            return 0
        read = _tls.mbedtls_ssl_read(&self._ctx, &buffer[0], amt)
        if read > 0:
            return read
        if read == 0:
            raise RaggedEOF()
        if read == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        if read == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        if read == _tls.MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            _exc.check_error(read)  # raises
            assert 0, "unreachable"
        self._reset()
        _exc.check_error(read)  # raises
        assert 0, "unreachable"

    def write(self, const unsigned char[:] buffer not None):
        if buffer.size == 0:
            return 0
        cdef size_t written = 0
        while written != buffer.size:
            ret = _tls.mbedtls_ssl_write(
                &self._ctx, &buffer[written], buffer.size - written)
            if ret >= 0:
                written += ret
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
                raise WantReadError()
            elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
                raise WantWriteError()
            else:
                self._reset()
                _exc.check_error(ret)
        assert written == len(buffer)
        return len(self._output_buffer)

    def receive_from_network(self, data):
        # PEP 543
        # Append data to input buffer.
        self._input_buffer.write(data, len(data))

    def peek_outgoing(self, amt):
        # PEP 543
        # Read from output buffer.
        if amt == 0:
            return b""
        return self._output_buffer.peek(amt)

    def consume_outgoing(self, amt):
        """Consume `amt` bytes from the output buffer."""
        # PEP 543
        self._output_buffer.consume(amt)

    def getpeercert(self, binary_form=False):
        """Return the peer certificate, or None."""
        c_crt = _tls.mbedtls_ssl_get_peer_cert(&self._ctx)
        if c_crt is NULL:
            return None

        # See `CRT.to_DER()`.
        der = bytes(c_crt.raw.p[0:c_crt.raw.len])
        if binary_form:
            return der
        return _x509.CRT.from_DER(der)

    def selected_npn_protocol(self):
        return None

    def negotiated_protocol(self):
        cdef const char* protocol = _tls.mbedtls_ssl_get_alpn_protocol(
            &self._ctx)
        if protocol is NULL:
            return None
        return protocol.decode("ascii")

    def _cipher_suite(self):
        cdef const char* name = _tls.mbedtls_ssl_get_ciphersuite(&self._ctx)
        if name is NULL:
            return None
        ssl_version = self.negotiated_tls_version()
        secret_bits = None
        return name.decode("ascii"), ssl_version, secret_bits

    def cipher(self):
        cipher = self._cipher_suite()
        if cipher is None:
            return
        return cipher[0]

    @property
    def _handshake_state(self):
        return HandshakeStep(self._ctx.state)

    def do_handshake(self):
        self._handle_handshake_response(
            _tls.mbedtls_ssl_handshake_step(&self._ctx)
        )

    def _renegotiate(self):
        """Initialize an SSL renegotiation on the running connection."""
        self._handle_handshake_response(
            _tls.mbedtls_ssl_renegotiate(&self._ctx)
        )

    def _handle_handshake_response(self, ret):
        if ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        if ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        if ret == _tls.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
            self._reset()
            raise HelloVerifyRequest()
        if (
            ret == -0x7100
            and self._handshake_state is HandshakeStep.HANDSHAKE_OVER
        ):
            raise ValueError("handshake already over")
        if ret < 0:
            self._reset()
            _exc.check_error(ret)
        if ret == 0 and self._output_buffer:
            raise WantWriteError
        assert ret == 0

    def _get_channel_binding(self, cb_type="tls-unique"):
        return None

    def negotiated_tls_version(self):
        # Strings from `ssl_tls.c`.
        return {
            "DTLSv1.0": DTLSVersion.DTLSv1_0,
            "DTLSv1.2": DTLSVersion.DTLSv1_2,
            # "SSLv3.0": TLSVersion.SSLv3,
            "TLSv1.0": TLSVersion.TLSv1,
            "TLSv1.1": TLSVersion.TLSv1_1,
            "TLSv1.2": TLSVersion.TLSv1_2,
            "TLSV1.3": TLSVersion.TLSv1_3,
        }.get(_tls.mbedtls_ssl_get_version(&self._ctx).decode("ascii"))
