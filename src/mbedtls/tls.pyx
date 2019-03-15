"""TLS/SSL wrapper for socket objects."""

__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2018, Mathias Laurin"
__license__ = "MIT License"


cimport libc.stdio as c_stdio
from libc.stdlib cimport malloc, free

cimport mbedtls._net as _net
cimport mbedtls._random as _rnd
cimport mbedtls.pk as _pk
cimport mbedtls.tls as _tls
cimport mbedtls.x509 as _x509

import socket as _socket
from collections import namedtuple
try:
    from collections import abc
except ImportError:
    # Python 2.7
    import collections as abc
try:
    from contextlib import suppress
except ImportError:
    # Python 2.7
    from contextlib2 import suppress
from enum import Enum, IntEnum
from itertools import tee

import certifi
import cython

import mbedtls._random as _rnd
import mbedtls._ringbuf as _rb
import mbedtls.pk as _pk
from mbedtls.exceptions import *


cdef _rnd.Random __rng = _rnd.default_rng()


@cython.boundscheck(False)
cdef void _my_debug(void *ctx, int level,
                    const char *file, int line, const char *str) nogil:
    c_stdio.fprintf(<c_stdio.FILE *> ctx, "%s:%04d: %s", file, line, str)
    c_stdio.fflush(<c_stdio.FILE *> ctx)


def _enable_debug_output(_BaseConfiguration conf):
    _tls.mbedtls_ssl_conf_dbg(&conf._ctx, _my_debug, c_stdio.stdout)


@cython.boundscheck(False)
cdef int buffer_write(void *ctx, const unsigned char *buf, size_t len) nogil:
    """Copy `buf` to internal buffer."""
    c_ctx = <_rb.ring_buffer_ctx *>ctx
    if len == 0:
        return _tls.MBEDTLS_ERR_SSL_BAD_INPUT_DATA
    if len > _rb.c_capacity(c_ctx) - _rb.c_len(c_ctx):
        return _tls.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL

    return _rb.c_write(c_ctx, &buf[0], len)


@cython.boundscheck(False)
cdef int buffer_read(void *ctx, unsigned char *buf, const size_t len) nogil:
    """Copy internal buffer to `buf`."""
    c_ctx = <_rb.ring_buffer_ctx *>ctx
    return _rb.c_readinto(c_ctx, buf, len)


def _set_debug_level(int level):
    """Set debug level for logging."""
    _tls.mbedtls_debug_set_threshold(level)


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
        - hash.algorithms_available
        - hmac.algorithms_available

    """
    cdef const int* ids = _tls.mbedtls_ssl_list_ciphersuites()
    cdef size_t n = 0
    ciphersuites = []
    while ids[n]:
        ciphersuites.append(__get_ciphersuite_name(ids[n]))
        n += 1
    return ciphersuites


class NextProtocol(Enum):
    # PEP 543
    H2 = b'h2'
    H2C = b'h2c'
    HTTP1 = b'http/1.1'
    WEBRTC = b'webrtc'
    C_WEBRTC = b'c-webrtc'
    FTP = b'ftp'
    STUN = b'stun.nat-discovery'
    TURN = b'stun.turn'


class TLSVersion(Enum):
    # PEP 543
    # SSLv3 is not safe and is disabled by default.
    # SSLv3 = _tls.MBEDTLS_SSL_MINOR_VERSION_0
    TLSv1 = _tls.MBEDTLS_SSL_MINOR_VERSION_1
    TLSv1_1 = _tls.MBEDTLS_SSL_MINOR_VERSION_2
    TLSv1_2 = _tls.MBEDTLS_SSL_MINOR_VERSION_3
    MINIMUM_SUPPORTED = TLSv1
    MAXIMUM_SUPPORTED = TLSv1_2


class DTLSVersion(Enum):
    DTLSv1_0 = _tls.MBEDTLS_SSL_MINOR_VERSION_2
    DTLSv1_2 = _tls.MBEDTLS_SSL_MINOR_VERSION_3
    MINIMUM_SUPPORTED = DTLSv1_0
    MAXIMUM_SUPPORTED = DTLSv1_2


class HandshakeStep(Enum):
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
    SERVER_HELLO_VERIFY_REQUEST_SENT = _tls.MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT


PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


class WantWriteError(TLSError):
    pass


class WantReadError(TLSError):
    pass


class RaggedEOF(TLSError):
    pass


class HelloVerifyRequest(TLSError):
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
        with open(str(path)) as cacert:
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

    def __getitem__(self, index):
        return self._db[index]

    def add(self, _x509.CRT crt):
        if crt in self:
            return
        cdef _x509.CRT c_crt
        if self._db:
            c_crt = self._db[-1]
            c_crt.set_next(crt)
        self._db.append(crt)


class Purpose(IntEnum):
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


cdef class _BaseConfiguration:

    """(D)TLS configuration."""

    def __init__(
        self,
        validate_certificates=None,
        certificate_chain=None,
        ciphers=None,
        inner_protocols=None,
        lowest_supported_version=None,
        highest_supported_version=None,
        trust_store=None,
        sni_callback=None,
        _transport=None,
    ):
        check_error(_tls.mbedtls_ssl_config_defaults(
            &self._ctx,
            endpoint=0,  # server / client is not known here...
            transport=_transport,
            preset=_tls.MBEDTLS_SSL_PRESET_DEFAULT))

        self._set_validate_certificates(validate_certificates)
        self._set_certificate_chain(certificate_chain)
        self._set_ciphers(ciphers)
        self._set_inner_protocols(inner_protocols)
        self._set_lowest_supported_version(lowest_supported_version)
        self._set_highest_supported_version(highest_supported_version)
        self._set_trust_store(trust_store)
        self._set_sni_callback(sni_callback)

        # Set random engine.
        _tls.mbedtls_ssl_conf_rng(
            &self._ctx, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx)

        # Disable renegotiation.
        _tls.mbedtls_ssl_conf_renegotiation(&self._ctx, 0)

    def __cinit__(self):
        _tls.mbedtls_ssl_config_init(&self._ctx)

        cdef int ciphers_sz = len(ciphers_available()) + 1
        self._ciphers = <int *>malloc(ciphers_sz * sizeof(int))
        if not self._ciphers:
            raise MemoryError()
        for idx in range(ciphers_sz):
            self._ciphers[idx] = 0

        cdef int protos_sz = len(NextProtocol) + 1
        self._protos = <char **>malloc(protos_sz * sizeof(char *))
        if not self._protos:
            raise MemoryError()
        for idx in range(protos_sz):
            self._protos[idx] = NULL

    def __dealloc__(self):
        _tls.mbedtls_ssl_config_free(&self._ctx)
        free(self._ciphers)
        free(self._protos)

    def __repr__(self):
        return ("%s("
                "validate_certificates=%r, "
                "certificate_chain=%r, "
                "ciphers=%r, "
                "inner_protocols=%r, "
                "lowest_supported_version=%r, "
                "highest_supported_version=%r, "
                "trust_store=%r, "
                "sni_callback=%r)"
                % (type(self).__name__,
                   self.validate_certificates,
                   self.certificate_chain,
                   self.ciphers,
                   self.inner_protocols,
                   self.lowest_supported_version,
                   self.highest_supported_version,
                   self.trust_store,
                   self.sni_callback))

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
        certs, pk_key = chain
        if not certs or not pk_key:
            return
        cdef _x509.CRT c_crt, c_crt_next
        for c_crt, c_crt_next in pairwise(certs):
            c_crt.set_next(c_crt_next)
        c_crt = certs[0]
        c_pk_key = <_pk.CipherBase?> pk_key
        check_error(_tls.mbedtls_ssl_conf_own_cert(
            &self._ctx, &c_crt._ctx, &c_pk_key._ctx))

    @property
    def certificate_chain(self):
        key_cert = self._ctx.key_cert
        if key_cert is NULL:
            return ((), None)
        chain = []
        cdef _x509.mbedtls_x509_crt *c_ctx = key_cert.cert
        while c_ctx is not NULL:
            chain.append(_x509.CRT.from_DER(c_ctx.raw.p[0:c_ctx.raw.len]))
            c_ctx = c_ctx.next
        cdef _pk.mbedtls_pk_context *c_key = key_cert.key
        cdef unsigned char[:] buf = bytearray(_pk.PRV_DER_MAX_BYTES)
        olen = check_error(
            _pk.mbedtls_pk_write_key_der(c_key, &buf[0], buf.size))
        cls = {
            0: _pk.ECC,
            1: _pk.RSA,
        }[_pk.mbedtls_pk_can_do(c_key, _pk.MBEDTLS_PK_RSA)]
        key = cls.from_DER(buf[buf.size - olen:buf.size])
        return tuple(chain), key

    cdef _set_ciphers(self, ciphers):
        """The available ciphers for the TLS connections.

        Args:
            ciphers (Tuple[Union[CipherSuite, int]]): The ciphers.

        """ # PEP 543
        if ciphers is None:
            return
        if len(ciphers) > len(ciphers_available()):
            raise ValueError("invalid ciphers")
        cdef size_t idx = 0
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
        cdef size_t idx
        for idx in range(len(ciphers_available())):
            cipher_id = self._ciphers[idx]
            if cipher_id == 0:
                break
            ciphers.append(__get_ciphersuite_name(cipher_id))
        return ciphers

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
        cdef size_t idx = 0
        self._protos[idx] = NULL
        for idx, proto in enumerate(protocols):
            if not isinstance(proto, bytes):
                proto = proto.value
            self._protos[idx] = proto
        self._protos[idx + 1] = NULL
        check_error(_tls.mbedtls_ssl_conf_alpn_protocols(
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
        if version is None:
            return
        _tls.mbedtls_ssl_conf_min_version(
            &self._ctx,
            _tls.MBEDTLS_SSL_MAJOR_VERSION_3,
            version.value)

    @property
    def lowest_supported_version(self):
        raise NotImplementedError

    cdef _set_highest_supported_version(self, version):
        """The maximum version of TLS that should be allowed.

        Args:
            version (TLSVersion, or DTLSVersion): The maximum version.

        """  # PEP 543
        if version is None:
            return
        _tls.mbedtls_ssl_conf_max_version(
            &self._ctx,
            _tls.MBEDTLS_SSL_MAJOR_VERSION_3,
            version.value)

    @property
    def highest_supported_version(self):
        raise NotImplementedError

    cdef _set_trust_store(self, store):
        """The trust store that connections will use.

        Args:
            store (TrustStore): The trust store.

        """ # PEP 543
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

    cdef _set_sni_callback(self, callback):
        # PEP 543, optional, server-side only
        if callback is None:
            return
        # mbedtls_ssl_conf_sni
        raise NotImplementedError

    @property
    def sni_callback(self):
        return None

    def update(self, *args):
        raise NotImplementedError


cdef class TLSConfiguration(_BaseConfiguration):
    """TLS configuration."""
    def __init__(
        self,
        validate_certificates=None,
        certificate_chain=None,
        ciphers=None,
        inner_protocols=None,
        lowest_supported_version=None,
        highest_supported_version=None,
        trust_store=None,
        sni_callback=None,
    ):
        super().__init__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            sni_callback=sni_callback,
            _transport=_tls.MBEDTLS_SSL_TRANSPORT_STREAM,
        )

    @property
    def lowest_supported_version(self):
        return TLSVersion(self._ctx.min_minor_ver)

    @property
    def highest_supported_version(self):
        return TLSVersion(self._ctx.max_minor_ver)

    def update(
        self,
        validate_certificates=_DEFAULT_VALUE,
        certificate_chain=_DEFAULT_VALUE,
        ciphers=_DEFAULT_VALUE,
        inner_protocols=_DEFAULT_VALUE,
        lowest_supported_version=_DEFAULT_VALUE,
        highest_supported_version=_DEFAULT_VALUE,
        trust_store=_DEFAULT_VALUE,
        sni_callback=_DEFAULT_VALUE,
    ):
        """Create a new ``TLSConfiguration``.

        Override some of the settings on the original configuration
        with the new settings.

        """
        if validate_certificates is _DEFAULT_VALUE:
            validate_certificates = self.validate_certificates

        if certificate_chain is _DEFAULT_VALUE:
            certificate_chain = self.certificate_chain

        if ciphers is _DEFAULT_VALUE:
            ciphers = self.ciphers

        if inner_protocols is _DEFAULT_VALUE:
            inner_protocols = self.inner_protocols

        if lowest_supported_version is _DEFAULT_VALUE:
            lowest_supported_version = self.lowest_supported_version

        if highest_supported_version is _DEFAULT_VALUE:
            highest_supported_version = self.highest_supported_version

        if trust_store is _DEFAULT_VALUE:
            trust_store = self.trust_store

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        return self.__class__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            sni_callback=sni_callback,
        )


cdef class DTLSConfiguration(_BaseConfiguration):
    """DTLS configuration."""
    def __init__(
        self,
        validate_certificates=None,
        certificate_chain=None,
        ciphers=None,
        inner_protocols=None,
        lowest_supported_version=None,
        highest_supported_version=None,
        trust_store=None,
        anti_replay=None,
        # badmac_limit
        # handshake_timeout
        sni_callback=None,
    ):
        super().__init__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            sni_callback=sni_callback,
            _transport=_tls.MBEDTLS_SSL_TRANSPORT_DATAGRAM,
        )
        self._set_anti_replay(anti_replay)
        # For security reasons, we do not make cookie optional here.
        cdef _tls._DTLSCookie cookie = _tls._DTLSCookie()
        cookie.generate()
        self._set_cookie(cookie)

    @property
    def lowest_supported_version(self):
        return DTLSVersion(self._ctx.min_minor_ver)

    @property
    def highest_supported_version(self):
        return DTLSVersion(self._ctx.max_minor_ver)

    cdef _set_anti_replay(self, anti_replay):
        """Set anti replay."""
        if anti_replay is None:
            return
        _tls.mbedtls_ssl_conf_dtls_anti_replay(
            &self._ctx,
            _tls.MBEDTLS_SSL_ANTI_REPLAY_ENABLED
            if anti_replay else
            _tls.MBEDTLS_SSL_ANTI_REPLAY_DISABLED)

    @property
    def anti_replay(self):
        cdef unsigned int enabled = _tls.MBEDTLS_SSL_ANTI_REPLAY_ENABLED
        return True if self._ctx.anti_replay == enabled else False

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

    def update(
        self,
        validate_certificates=_DEFAULT_VALUE,
        certificate_chain=_DEFAULT_VALUE,
        ciphers=_DEFAULT_VALUE,
        inner_protocols=_DEFAULT_VALUE,
        lowest_supported_version=_DEFAULT_VALUE,
        highest_supported_version=_DEFAULT_VALUE,
        trust_store=_DEFAULT_VALUE,
        sni_callback=_DEFAULT_VALUE,
        anti_replay=_DEFAULT_VALUE,
    ):
        """Create a new ``DTLSConfiguration``.

        Override some of the settings on the original configuration
        with the new settings.

        """
        if validate_certificates is _DEFAULT_VALUE:
            validate_certificates = self.validate_certificates

        if certificate_chain is _DEFAULT_VALUE:
            certificate_chain = self.certificate_chain

        if ciphers is _DEFAULT_VALUE:
            ciphers = self.ciphers

        if inner_protocols is _DEFAULT_VALUE:
            inner_protocols = self.inner_protocols

        if lowest_supported_version is _DEFAULT_VALUE:
            lowest_supported_version = self.lowest_supported_version

        if highest_supported_version is _DEFAULT_VALUE:
            highest_supported_version = self.highest_supported_version

        if trust_store is _DEFAULT_VALUE:
            trust_store = self.trust_store

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        if anti_replay is _DEFAULT_VALUE:
            anti_replay = self.anti_replay

        return self.__class__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            sni_callback=sni_callback,
            anti_replay=anti_replay,
        )


DEFAULT_CIPHER_LIST = None


cdef class _TLSSession:
    def __cinit__(self):
        """Initialize SSL session structure."""
        _tls.mbedtls_ssl_session_init(&self._ctx)

    def __dealloc__(self):
        """Free referenced items in an SSL session."""
        _tls.mbedtls_ssl_session_free(&self._ctx)


cdef class _BaseContext:
    # _pep543._BaseContext
    """Context base class.

    Args:
        configuration (TLSConfiguration): The configuration.

    """
    def __init__(self, _BaseConfiguration configuration not None):
        self._conf = configuration
        check_error(_tls.mbedtls_ssl_setup(&self._ctx, &self._conf._ctx))

    def __cinit__(self):
        """Initialize an `ssl_context`."""
        _tls.mbedtls_ssl_init(&self._ctx)
        _tls.mbedtls_ssl_set_timer_cb(
            &self._ctx,
            &self._timer,
            _tls.mbedtls_timing_set_delay,
            _tls.mbedtls_timing_get_delay)

    def __dealloc__(self):
        """Free and clear the internal structures of ctx."""
        _tls.mbedtls_ssl_free(&self._ctx)

    @property
    def configuration(self):
        # PEP 543
        return self._conf

    @property
    def _purpose(self):
        return Purpose(self._conf._ctx.endpoint)

    def _reset(self):
        check_error(_tls.mbedtls_ssl_session_reset(&self._ctx))

    def _shutdown(self):
        _tls.mbedtls_ssl_close_notify(&self._ctx)
        self._reset()

    def _close(self):
        self._shutdown()

    def _readinto(self, unsigned char[:] buffer, size_t amt):
        if amt <= 0:
            return 0
        # cdef size_t avail = _tls.mbedtls_ssl_get_bytes_avail(&self._ctx)
        read = _tls.mbedtls_ssl_read(&self._ctx, &buffer[0], amt)
        if read > 0:
            return read
        elif read == 0:
            raise RaggedEOF()
        elif read == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        elif read == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        elif read == _tls.MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            check_error(read)
        else:
            self._reset()
            check_error(read)

    def _write(self, const unsigned char[:] buffer):
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
                check_error(ret)
        return written

    # def getpeercert(self, binary_form=False):
    #     crt = _tls.mbedtls_ssl_get_peer_cert()

    def _selected_npn_protocol(self):
        return None

    def _negotiated_protocol(self):
        cdef const char* protocol = _tls.mbedtls_ssl_get_alpn_protocol(
            &self._ctx)
        if protocol is NULL:
            return None
        return protocol.decode("ascii")

    def _cipher(self):
        cdef const char* name = _tls.mbedtls_ssl_get_ciphersuite(&self._ctx)
        if name is NULL:
            return None
        ssl_version = self._negotiated_tls_version()
        secret_bits = None
        return name.decode("ascii"), ssl_version, secret_bits

    @property
    def _state(self):
        return HandshakeStep(self._ctx.state)

    def _do_handshake_step(self):
        ret = _tls.mbedtls_ssl_handshake_step(&self._ctx)
        if ret == 0:
            return self._state
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        else:
            self._reset()
            check_error(ret)
            return self._state

    def _do_handshake(self):
        """Start the SSL/TLS handshake."""
        ret = _tls.mbedtls_ssl_handshake(&self._ctx)
        if ret == 0:
            return
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        elif ret == _tls.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
            self._reset()
            raise HelloVerifyRequest()
        else:
            assert ret < 0
            self._reset()
            check_error(ret)

    def _renegotiate(self):
        """Initialize an SSL renegotiation on the running connection."""
        ret = _tls.mbedtls_ssl_renegotiate(&self._ctx)
        if ret == 0:
            return
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_READ:
            raise WantReadError()
        elif ret == _tls.MBEDTLS_ERR_SSL_WANT_WRITE:
            raise WantWriteError()
        else:
            assert ret < 0
            self._reset()
            check_error(ret)

    def _get_channel_binding(self, cb_type="tls-unique"):
        return None

    def _negotiated_tls_version(self):
        # Strings from `ssl_tls.c`.
        return {
            "DTLSv1.0": DTLSVersion.DTLSv1_0,
            "DTLSv1.2": DTLSVersion.DTLSv1_2,
            # "SSLv3.0": TLSVersion.SSLv3,
            "TLSv1.0": TLSVersion.TLSv1,
            "TLSv1.1": TLSVersion.TLSv1_1,
            "TLSv1.2": TLSVersion.TLSv1_2,
        }.get(_tls.mbedtls_ssl_get_version(&self._ctx).decode("ascii"))


cdef class ClientContext(_BaseContext):
    # _pep543.ClientContext

    def __init__(self, _BaseConfiguration configuration not None):
        _tls.mbedtls_ssl_conf_endpoint(
            &configuration._ctx, _tls.MBEDTLS_SSL_IS_CLIENT)
        super(ClientContext, self).__init__(configuration)

    def wrap_socket(self, socket, server_hostname):
        """Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        Args:
            socket (socket.socket): The socket to wrap.
            server_hostname (str, optional): The hostname of the service
                which we are connecting to.  Pass ``None`` if hostname
                validation is not desired.  This parameter has no
                default value because opting-out hostname validation is
                dangerous and should not be the default behavior.

        """
        buffer = self.wrap_buffers(server_hostname)
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self, server_hostname):
        """Create an in-memory stream for TLS."""
        # PEP 543
        if server_hostname is not None:
            self._set_hostname(server_hostname)
        return TLSWrappedBuffer(self)

    def _set_hostname(self, hostname):
        """Set the hostname to check against the received server."""
        if hostname is None:
            return
        # Note: `ssl_set_hostname()` makes a copy so it is safe
        #       to call with the temporary `hostname_`.
        hostname_ = hostname.encode("utf8")
        cdef const char* c_hostname = hostname_
        check_error(_tls.mbedtls_ssl_set_hostname(&self._ctx, c_hostname))

    @property
    def _hostname(self):
        if self._ctx.hostname is NULL:
            return None
        return (<bytes> self._ctx.hostname).decode("utf8")


cdef class ServerContext(_BaseContext):
    # _pep543.ServerContext

    def __init__(self, _BaseConfiguration configuration not None):
        _tls.mbedtls_ssl_conf_endpoint(
            &configuration._ctx, _tls.MBEDTLS_SSL_IS_SERVER)
        super(ServerContext, self).__init__(configuration)

    def wrap_socket(self, socket):
        """Wrap an existing Python socket object ``socket``."""
        buffer = self.wrap_buffers()
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self):
        # PEP 543
        return TLSWrappedBuffer(self)

    def _setcookieparam(self, const unsigned char[:] info):
        _tls.mbedtls_ssl_set_client_transport_id(
            &self._ctx,
            &info[0],
            info.size,
        )

    @property
    def _cookieparam(self):
        """Client ID for the HelloVerifyRequest.

        Notes:
            DTLS only.

        """
        client_id = bytes(self._ctx.cli_id[0:self._ctx.cli_id_len])
        return client_id if client_id else None


cdef class TLSWrappedBuffer:
    # _pep543.TLSWrappedBuffer
    def __init__(self, _BaseContext context):
        self._context = context
        self._buffer = _rb.RingBuffer(_tls.TLS_BUFFER_CAPACITY)
        self.context._reset()

    cdef void _as_bio(self):
        _tls.mbedtls_ssl_set_bio(
            &(<_tls._BaseContext>self.context)._ctx,
            &self._buffer._ctx,
            buffer_write,
            buffer_read,
            NULL)

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.context)

    def __bytes__(self):
        return bytes(self._buffer)

    def read(self, size_t amt):
        # PEP 543
        if amt <= 0:
            return b""
        buffer = bytearray(amt)
        return bytes(buffer[:self.readinto(buffer, amt)])

    def readinto(self, unsigned char[:] buffer, size_t amt):
        # PEP 543
        if buffer.size == 0:
            return 0
        return self.context._readinto(buffer, amt)

    def write(self, const unsigned char[:] buffer):
        # PEP 543
        assert self._buffer.empty(), "%i bytes in buffer" % len(self._buffer)
        amt = self.context._write(buffer)
        assert amt == buffer.size
        return len(self._buffer)

    def _do_handshake_step(self):
        return self.context._do_handshake_step()

    def do_handshake(self):
        # PEP 543
        self.context._do_handshake()

    def _setcookieparam(self, param):
        self.context._setcookieparam(param)

    def cipher(self):
        # PEP 543
        cipher = self.context._cipher()
        if cipher is None:
            return cipher
        else:
            return cipher[0]

    def negotiated_protocol(self):
        # PEP 543
        return self.context._negotiated_protocol()

    @property
    def context(self):
        # PEP 543
        """The ``Context`` object this buffer is tied to."""
        return self._context

    def negotiated_tls_version(self):
        # PEP 543
        return self.context._negotiated_tls_version()

    def shutdown(self):
        # PEP 543
        self.context._shutdown()

    def receive_from_network(self, const unsigned char[:] data not None):
        # PEP 543
        # Append data to input buffer.
        self._buffer.write(data, data.size)

    def peek_outgoing(self, size_t amt):
        # PEP 543
        # Read from output buffer.
        if amt == 0:
            return b""
        return self._buffer.peek(amt)

    def consume_outgoing(self, size_t amt):
        """Consume `amt` bytes from the output buffer."""
        # PEP 543
        self._buffer.consume(amt)


cdef class TLSWrappedSocket:
    # _pep543.TLSWrappedSocket
    def __init__(self, socket, TLSWrappedBuffer buffer):
        super().__init__()
        self._socket = socket
        self._buffer = buffer
        # Default to pass-through BIO.
        self._ctx.fd = <int>socket.fileno()
        self._as_bio()

    def __cinit__(self, socket, TLSWrappedBuffer buffer):
        _net.mbedtls_net_init(&self._ctx)

    def __dealloc__(self):
        _net.mbedtls_net_free(&self._ctx)

    cdef void _as_bio(self):
        _tls.mbedtls_ssl_set_bio(
            &(<_tls._BaseContext>self.context)._ctx,
            &self._ctx,
            _net.mbedtls_net_send,
            _net.mbedtls_net_recv,
            _net.mbedtls_net_recv_timeout)

    def __str__(self):
        return str(self._socket)

    # PEP 543 requires the full socket API.

    @property
    def family(self):
        return self._socket.family

    @property
    def proto(self):
        return self._socket.proto

    @property
    def type(self):
        return self._socket.type

    def accept(self):
        if self.type == _socket.SOCK_STREAM:
            conn, address = self._socket.accept()
        else:
            data, address = self._socket.recvfrom(1, _socket.MSG_PEEK)
            assert data, "no data"

            # Use this socket to communicate with the client and bind
            # another one for the next connection.  This procedure is
            # adapted from `mbedtls_net_accept()`.
            sockname = self.getsockname()
            conn = _socket.fromfd(self.fileno(), self.family, self.type)
            conn.connect(address)
            self.close()
            self._socket = _socket.socket(self.family, self.type, self.proto)
            self.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            self.bind(sockname)
        return self.context.wrap_socket(conn), address

    def bind(self, address):
        self._socket.bind(address)

    def close(self):
        self._buffer.shutdown()
        self._socket.close()

    def connect(self, address):
        self._socket.connect(address)

    def connect_ex(self, address):
        self._socket.connect_ex(address)

    def fileno(self):
        return self._socket.fileno()

    def getpeername(self):
        return self._socket.getpeername()

    def getsockname(self):
        return self._socket.getsockname()

    def getsockopt(self, optname, buflen=None):
        return self._socket.getsockopt(optname, buflen=buflen)

    def listen(self, backlog=None):
        if backlog is None:
            # Use 5 (Python default) or 10 (mbedtls defaults).
            backlog = 5
        self._socket.listen(backlog)

    def makefile(self, *args, **kwargs):
        return self._socket.makefile(*args, **kwargs)

    def recv(self, size_t bufsize, flags=0):
        encrypted = self._socket.recv(bufsize, flags)
        if not encrypted:
            return b""
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize)

    def recv_into(self, buffer, nbytes=None, flags=0):
        raise NotImplementedError

    def recvfrom(self, bufsize, flags=0):
        encrypted, addr = self._socket.recvfrom(bufsize, flags)
        if not encrypted:
            return b"", addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize), addr

    def recvfrom_into(self, unsigned char[:] buffer, nbytes=None, flags=0):
        encrypted, addr = self._socker.recvfrom(bufsize, flags)
        if not encrypted:
            return buffer, addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.readinto(buffer, nbytes), addr

    def send(self, const unsigned char[:] message, flags=0):
        # Maximum size supported by TLS is 16K (encrypted).
        # mbedTLS defines it in MBEDTLS_SSL_MAX_CONTENT_LEN and
        # MBEDTLS_SSL_IN_CONTENT_LEN/MBEDTLS_SSL_OUT_CONTENT_LEN.
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._socket.send(encrypted, flags)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def sendall(self, const unsigned char[:] message, flags=0):
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._buffer.consume_outgoing(amt)
        self._socket.sendall(encrypted)

    def sendto(self, message, flags=0, address=None):
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        if address:
            self._socket.sendto(encrypted, flags, address)
        else:
            self._socket.sendto(encrypted, flags)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def setblocking(self, flag):
        self._socket.setblocking(flag)

    def settimeout(self, value):
        self._socket.settimeout(value)

    def gettimeout(self):
        return self._socket.gettimeout()

    def setsockopt(self, level, optname, value):
        self._socket.setsockopt(level, optname, value)

    def shutdown(self, how):
        self._buffer.shutdown()
        self._socket.shutdown(how)

    # PEP 543 adds the following methods.

    def _do_handshake_step(self):
        self._as_bio()
        state = self._buffer._do_handshake_step()
        if state is HandshakeStep.HANDSHAKE_OVER:
            self._buffer._as_bio()
        return state

    def do_handshake(self):
        self._as_bio()
        self._buffer.do_handshake()
        self._buffer._as_bio()

    def setcookieparam(self, param):
        self._buffer._setcookieparam(param)

    def cipher(self):
        return self._buffer.cipher()

    def negotiated_protocol(self):
        return self._buffer.negotiated_protocol()

    @property
    def context(self):
        return self._buffer.context

    def negotiated_tls_version(self):
        return self._buffer.negotiated_tls_version()

    def unwrap(self):
        self._buffer.shutdown()
        self.shutdown(_socket.SHUT_RDWR)
        return self._socket
