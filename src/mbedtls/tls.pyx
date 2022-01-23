# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

"""TLS/SSL wrapper for socket objects."""


cimport libc.stdio as c_stdio
from libc.stdlib cimport malloc, free

cimport mbedtls._net as _net
cimport mbedtls._random as _rnd
cimport mbedtls.pk as _pk
cimport mbedtls.tls as _tls
cimport mbedtls.x509 as _x509

import enum
import socket as _socket
import struct
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

from itertools import tee

import certifi
import cython

import mbedtls._random as _rnd
import mbedtls._ringbuf as _rb
import mbedtls.exceptions as _exc
import mbedtls.pk as _pk


cdef _rnd.Random __rng = _rnd.default_rng()


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
                    const char *file, int line, const char *str) nogil:
    c_stdio.fprintf(<c_stdio.FILE *> ctx, "%s:%04d: %s", file, line, str)
    c_stdio.fflush(<c_stdio.FILE *> ctx)


def _enable_debug_output(_BaseConfiguration conf):
    _tls.mbedtls_ssl_conf_dbg(&conf._ctx, _my_debug, c_stdio.stdout)


@cython.boundscheck(False)
cdef int buffer_write(void *ctx, const unsigned char *buf, size_t len) nogil:
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
cdef int buffer_read(void *ctx, unsigned char *buf, const size_t len) nogil:
    """Read from input buffer."""
    c_buf = <_tls._C_Buffers *> ctx
    if _rb.c_len(c_buf.in_ctx) == 0:
        return _tls.MBEDTLS_ERR_SSL_WANT_WRITE
    return _rb.c_readinto(c_buf.in_ctx, buf, len)


@cython.boundscheck(False)
cdef int _psk_cb(
    void *parameter,
    _tls.mbedtls_ssl_context *ctx,
    const unsigned char *c_identity,
    size_t c_identity_len
) nogil:
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


@enum.unique
class NextProtocol(enum.Enum):
    # PEP 543
    H2 = b'h2'
    H2C = b'h2c'
    HTTP1 = b'http/1.1'
    WEBRTC = b'webrtc'
    C_WEBRTC = b'c-webrtc'
    FTP = b'ftp'
    STUN = b'stun.nat-discovery'
    TURN = b'stun.turn'


class TLSVersion(enum.IntEnum):
    # MBEDTLS_SSL_|MAJOR|MINOR|_VERSION
    # PEP 543
    # SSLv3 is not safe and is disabled by default.
    # SSLv3 = 0x300
    TLSv1 = 0x301
    TLSv1_1 = 0x302
    TLSv1_2 = 0x303
    MINIMUM_SUPPORTED = TLSv1
    MAXIMUM_SUPPORTED = TLSv1_2

    @classmethod
    def from_major_minor(cls, major, minor):
        return cls((major << 8) + minor)

    def major(self):
        return (self >> 8) & 0xFF

    def minor(self):
        return self & 0xFF


class DTLSVersion(enum.IntEnum):
    DTLSv1_0 = 0x302
    DTLSv1_2 = 0x303
    MINIMUM_SUPPORTED = DTLSv1_0
    MAXIMUM_SUPPORTED = DTLSv1_2

    @classmethod
    def from_major_minor(cls, major, minor):
        return cls((major << 8) + minor)

    def major(self):
        return (self >> 8) & 0xFF

    def minor(self):
        return self & 0xFF


class TLSRecordHeader:
    """Encode/decode TLS record protocol format."""

    __slots__ = ("record_type", "version", "length")
    fmt = "!BHH"

    class RecordType(enum.IntEnum):
        CHANGE_CIPHER_SPEC = 0x14
        ALERT = 0x15
        HANDSHAKE = 0x16
        APPLICATION_DATA = 0x17

    def __init__(self, record_type, version, length):
        self.record_type = record_type
        self.version = version
        self.length = length

    def __str__(self):
        return "%s(%s, %s, %s)" % (type(self).__name__, self.record_type, self.version, self.length)

    def __repr__(self):
        return "%s(%r, %r, %r)" % (type(self).__name__, self.record_type, self.version, self.length)

    def __eq__(self, other):
        if not isinstance(other, TLSRecordHeader):
            return NotImplemented
        return (self.record_type is other.record_type and
                self.version is other.version and
                self.length == other.length)

    def __hash__(self):
        return 0x5AFE ^ self.record_type ^ self.version ^ self.length

    def __len__(self):
        return 5

    def __bytes__(self):
        return struct.pack(TLSRecordHeader.fmt, self.record_type, self.version, self.length)

    @classmethod
    def from_bytes(cls, header):
        record_type, version, length = struct.unpack(TLSRecordHeader.fmt, header[:5])
        return cls(
            TLSRecordHeader.RecordType(record_type),
            TLSVersion(version),
            length,
        )


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
    SERVER_HELLO_VERIFY_REQUEST_SENT = _tls.MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT


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
        pre_shared_key=None,
        pre_shared_key_store=None,
        _transport=None,
    ):
        _exc.check_error(_tls.mbedtls_ssl_config_defaults(
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
        self._set_pre_shared_key(pre_shared_key)
        self._set_pre_shared_key_store(pre_shared_key_store)

        # Set random engine.
        _tls.mbedtls_ssl_conf_rng(
            &self._ctx, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx)

        # Disable renegotiation.
        _tls.mbedtls_ssl_conf_renegotiation(&self._ctx, 0)

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
            return ((), None)
        chain = []
        cdef _x509.mbedtls_x509_crt *c_ctx = key_cert.cert
        while c_ctx is not NULL:
            chain.append(_x509.CRT.from_DER(c_ctx.raw.p[0:c_ctx.raw.len]))
            c_ctx = c_ctx.next
        cdef _pk.mbedtls_pk_context *c_key = key_cert.key
        cdef unsigned char[:] buf = bytearray(_pk.PRV_DER_MAX_BYTES)
        olen = _exc.check_error(
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
        if version is None:
            return
        _tls.mbedtls_ssl_conf_min_version(
            &self._ctx,
            version.major(),
            version.minor(),
        )

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
            version.major(),
            version.minor(),
        )

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
        pre_shared_key=None,
        pre_shared_key_store=None,
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
            pre_shared_key=pre_shared_key,
            pre_shared_key_store=pre_shared_key_store,
            _transport=_tls.MBEDTLS_SSL_TRANSPORT_STREAM,
        )

    @property
    def lowest_supported_version(self):
        return TLSVersion.from_major_minor(
            self._ctx.min_major_ver, self._ctx.min_minor_ver)

    @property
    def highest_supported_version(self):
        return TLSVersion.from_major_minor(
            self._ctx.max_major_ver, self._ctx.max_minor_ver)

    def __repr__(self):
        return ("%s("
                "validate_certificates=%r, "
                "certificate_chain=%r, "
                "ciphers=%r, "
                "inner_protocols=%r, "
                "lowest_supported_version=%s, "
                "highest_supported_version=%s, "
                "trust_store=%r, "
                "sni_callback=%r, "
                "pre_shared_key=%r, "
                "pre_shared_key_store=%r)"
                % (type(self).__name__,
                   self.validate_certificates,
                   self.certificate_chain,
                   self.ciphers,
                   self.inner_protocols,
                   self.lowest_supported_version,
                   self.highest_supported_version,
                   self.trust_store,
                   self.sni_callback,
                   self.pre_shared_key,
                   self.pre_shared_key_store,
                  ))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return all(
            (
                self.validate_certificates == other.validate_certificates,
                self.certificate_chain == other.certificate_chain,
                self.ciphers == other.ciphers,
                self.inner_protocols == other.inner_protocols,
                self.lowest_supported_version == other.lowest_supported_version,
                self.highest_supported_version == other.highest_supported_version,
                self.trust_store == other.trust_store,
                self.sni_callback == other.sni_callback,
                self.pre_shared_key == other.pre_shared_key,
                self.pre_shared_key_store == other.pre_shared_key_store,
            )
        )

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
                self.sni_callback,
                self.pre_shared_key,
                self.pre_shared_key_store,
            ),
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
        pre_shared_key=_DEFAULT_VALUE,
        pre_shared_key_store=_DEFAULT_VALUE,
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

        if pre_shared_key is _DEFAULT_VALUE:
            pre_shared_key = self.pre_shared_key

        if pre_shared_key_store is _DEFAULT_VALUE:
            pre_shared_key_store = self.pre_shared_key_store

        return self.__class__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            sni_callback=sni_callback,
            pre_shared_key=pre_shared_key,
            pre_shared_key_store=pre_shared_key_store,
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
        handshake_timeout_min=None,
        handshake_timeout_max=None,
        sni_callback=None,
        pre_shared_key=None,
        pre_shared_key_store=None,
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
            pre_shared_key=pre_shared_key,
            pre_shared_key_store=pre_shared_key_store,
            _transport=_tls.MBEDTLS_SSL_TRANSPORT_DATAGRAM,
        )
        self._set_anti_replay(anti_replay)
        self._set_handshake_timeout(handshake_timeout_min, handshake_timeout_max)
        # For security reasons, we do not make cookie optional here.
        cdef _tls._DTLSCookie cookie = _tls._DTLSCookie()
        cookie.generate()
        self._set_cookie(cookie)

    @property
    def lowest_supported_version(self):
        return DTLSVersion.from_major_minor(
            self._ctx.min_major_ver, self._ctx.min_minor_ver)

    @property
    def highest_supported_version(self):
        return DTLSVersion.from_major_minor(
            self._ctx.max_major_ver, self._ctx.max_minor_ver)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return all(
            (
                self.validate_certificates == other.validate_certificates,
                self.certificate_chain == other.certificate_chain,
                self.ciphers == other.ciphers,
                self.inner_protocols == other.inner_protocols,
                self.lowest_supported_version == other.lowest_supported_version,
                self.highest_supported_version == other.highest_supported_version,
                self.trust_store == other.trust_store,
                self.anti_replay == other.anti_replay,
                self.handshake_timeout_min == other.handshake_timeout_min,
                self.handshake_timeout_max == other.handshake_timeout_max,
                self.sni_callback == other.sni_callback,
                self.pre_shared_key == other.pre_shared_key,
                self.pre_shared_key_store == other.pre_shared_key_store,
            )
        )

    def __repr__(self):
        return ("%s("
                "validate_certificates=%r, "
                "certificate_chain=%r, "
                "ciphers=%r, "
                "inner_protocols=%r, "
                "lowest_supported_version=%s, "
                "highest_supported_version=%s, "
                "trust_store=%r, "
                "anti_replay=%r, "
                "handshake_timeout_min=%r, "
                "handshake_timeout_max=%r, "
                "sni_callback=%r, "
                "pre_shared_key=%r, "
                "pre_shared_key_store=%r)"
                % (type(self).__name__,
                   self.validate_certificates,
                   self.certificate_chain,
                   self.ciphers,
                   self.inner_protocols,
                   self.lowest_supported_version,
                   self.highest_supported_version,
                   self.trust_store,
                   self.anti_replay,
                   self.handshake_timeout_min,
                   self.handshake_timeout_max,
                   self.sni_callback,
                   self.pre_shared_key,
                   self.pre_shared_key_store,
                  ))

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
                self.anti_replay,
                self.handshake_timeout_min,
                self.handshake_timeout_max,
                self.sni_callback,
                self.pre_shared_key,
                self.pre_shared_key_store,
            ),
        )

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

    cdef _set_handshake_timeout(self, minimum, maximum):
        """Set DTLS handshake timeout.

        Args:
            minimum (float, optional): minimum timeout in seconds.
            maximum (float, optional): maximum timeout in seconds.

        """
        if minimum is None and maximum is None:
            return

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
        return float(self._ctx.hs_timeout_min) / 1000.0

    @property
    def handshake_timeout_max(self):
        """Max handshake timeout in seconds (default 60.0)."""
        return float(self._ctx.hs_timeout_max) / 1000.0

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
        anti_replay=_DEFAULT_VALUE,
        handshake_timeout_min=_DEFAULT_VALUE,
        handshake_timeout_max=_DEFAULT_VALUE,
        sni_callback=_DEFAULT_VALUE,
        pre_shared_key=_DEFAULT_VALUE,
        pre_shared_key_store=_DEFAULT_VALUE,
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

        if anti_replay is _DEFAULT_VALUE:
            anti_replay = self.anti_replay

        if handshake_timeout_min is _DEFAULT_VALUE:
            handshake_timeout_min = self.handshake_timeout_min

        if handshake_timeout_max is _DEFAULT_VALUE:
            handshake_timeout_max = self.handshake_timeout_max

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        if pre_shared_key is _DEFAULT_VALUE:
            pre_shared_key = self.pre_shared_key

        if pre_shared_key_store is _DEFAULT_VALUE:
            pre_shared_key_store = self.pre_shared_key_store

        return self.__class__(
            validate_certificates=validate_certificates,
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
            anti_replay=anti_replay,
            handshake_timeout_min=handshake_timeout_min,
            handshake_timeout_max=handshake_timeout_max,
            sni_callback=sni_callback,
            pre_shared_key=pre_shared_key,
            pre_shared_key_store=pre_shared_key_store,
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

    def save(self, ClientContext context):
        try:
            _exc.check_error(
                _tls.mbedtls_ssl_get_session(&context._ctx, &self._ctx)
            )
        except _exc.TLSError as exc:
            raise ValueError(context) from exc

    def resume(self, _BaseConfiguration configuration not None):
        cdef ClientContext client = ClientContext(configuration)
        _exc.check_error(
            _tls.mbedtls_ssl_set_session(&client._ctx, &self._ctx)
        )
        return client


cdef class _BaseContext:
    # _pep543._BaseContext
    """Context base class.

    Args:
        configuration (TLSConfiguration): The configuration.

    """
    def __init__(self, _BaseConfiguration configuration not None):
        self._conf = configuration
        _exc.check_error(_tls.mbedtls_ssl_setup(&self._ctx, &self._conf._ctx))

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

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self._conf)

    @property
    def configuration(self):
        # PEP 543
        return self._conf

    @property
    def _purpose(self):
        return Purpose(self._conf._ctx.endpoint)

    @property
    def _verified(self):
        return _tls.mbedtls_ssl_get_verify_result(&self._ctx) == 0

    def _reset(self):
        _exc.check_error(_tls.mbedtls_ssl_session_reset(&self._ctx))

    def _shutdown(self):
        # This could also return SSL_WANT_READ / SSL_WANT_WRITE.
        _exc.check_error(_tls.mbedtls_ssl_close_notify(&self._ctx))
        self._reset()

    def _close(self):
        self._shutdown()

    def _readinto(self, unsigned char[:] buffer not None, size_t amt):
        if buffer.size == 0:
            return 0
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
            _exc.check_error(read)
        else:
            self._reset()
            _exc.check_error(read)

    def _write(self, const unsigned char[:] buffer not None):
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
        if self._state is HandshakeStep.HANDSHAKE_OVER:
            raise ValueError("handshake already over")
        self._handle_handshake_response(_tls.mbedtls_ssl_handshake_step(&self._ctx))

    def _renegotiate(self):
        """Initialize an SSL renegotiation on the running connection."""
        self._handle_handshake_response(_tls.mbedtls_ssl_renegotiate(&self._ctx))

    def _handle_handshake_response(self, ret):
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
            _exc.check_error(ret)

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
        _exc.check_error(_tls.mbedtls_ssl_set_hostname(&self._ctx, c_hostname))

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

    def _setcookieparam(self, const unsigned char[:] info not None):
        if info.size == 0:
            info = b"\0"
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
        self.context._reset()

    def __cinit__(self, _BaseContext context):
        self._output_buffer = _rb.RingBuffer(_tls.TLS_BUFFER_CAPACITY)
        self._input_buffer = _rb.RingBuffer(_tls.TLS_BUFFER_CAPACITY)
        self._c_buffers = _tls._C_Buffers(
            &self._output_buffer._ctx, &self._input_buffer._ctx
        )
        _tls.mbedtls_ssl_set_bio(
            &(<_tls._BaseContext>context)._ctx,
            &self._c_buffers,
            buffer_write,
            buffer_read,
            NULL)

    def __repr__(self):
        return "%s(%r)" % (type(self).__name__, self.context)

    def __getstate__(self):
        # We could make this pickable by copying the buffers.
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def read(self, size_t amt):
        # PEP 543
        if amt <= 0:
            return b""
        buffer = bytearray(amt)
        cdef unsigned char[:] c_buffer = buffer
        cdef size_t nread = 0
        while nread != amt and not self._input_buffer.empty():
            nread += self.readinto(c_buffer[nread:], amt - nread)
        return bytes(buffer[:nread])

    def readinto(self, unsigned char[:] buffer not None, size_t amt):
        # PEP 543
        return self.context._readinto(buffer, amt)

    def write(self, const unsigned char[:] buffer not None):
        # PEP 543
        amt = self.context._write(buffer)
        assert amt == buffer.size
        return len(self._output_buffer)

    def do_handshake(self):
        # PEP 543
        self.context._do_handshake_step()

    def _do_handshake_blocking(self, sock):
        while self._context._state is not HandshakeStep.HANDSHAKE_OVER:
            try:
                self.context._do_handshake_step()
                amt = sock.send(self.peek_outgoing(1024))
                self.consume_outgoing(amt)
            except WantReadError:
                amt = sock.send(self.peek_outgoing(1024))
                self.consume_outgoing(amt)
            except WantWriteError:
                data = sock.recv(1024)
                self.receive_from_network(data)

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
        self._input_buffer.write(data, data.size)

    def peek_outgoing(self, size_t amt):
        # PEP 543
        # Read from output buffer.
        if amt == 0:
            return b""
        return self._output_buffer.peek(amt)

    def consume_outgoing(self, size_t amt):
        """Consume `amt` bytes from the output buffer."""
        # PEP 543
        self._output_buffer.consume(amt)


cdef class TLSWrappedSocket:
    # _pep543.TLSWrappedSocket
    def __init__(self, socket, TLSWrappedBuffer buffer):
        super().__init__()
        self._socket = socket
        self._buffer = buffer
        self._closed = False

    def __cinit__(self):
        _net.mbedtls_net_init(&self._ctx)

    def __dealloc__(self):
        _net.mbedtls_net_free(&self._ctx)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        if not self._closed:
            self.close()

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
            _, address = self._socket.recvfrom(1024, _socket.MSG_PEEK)
            # Use this socket to communicate with the client and bind
            # another one for the next connection.  This procedure is
            # adapted from `mbedtls_net_accept()`.
            sockname = self.getsockname()
            conn = _socket.fromfd(self.fileno(), self.family, self.type)
            conn.connect(address)
            # Closing the socket on Python 2.7 and 3.4 invalidates
            # the accessors.  So we should get the values first.
            family, type_, proto = self.family, self.type, self.proto
            self.close()
            self._socket = _socket.socket(family, type_, proto)
            self.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            self.bind(sockname)
        return self.context.wrap_socket(conn), address

    def bind(self, address):
        self._socket.bind(address)

    def close(self):
        self._closed = True
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

    def recvfrom_into(
        self, unsigned char[:] buffer not None, nbytes=None, flags=0
    ):
        encrypted, addr = self._socket.recvfrom(buffer.size(), flags)
        if not encrypted:
            return buffer, addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.readinto(buffer, nbytes), addr

    def send(
        self, const unsigned char[:] message not None, flags=0
    ):
        # Maximum size supported by TLS is 16K (encrypted).
        # mbedTLS defines it in MBEDTLS_SSL_MAX_CONTENT_LEN and
        # MBEDTLS_SSL_IN_CONTENT_LEN/MBEDTLS_SSL_OUT_CONTENT_LEN.
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._socket.send(encrypted, flags)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def sendall(
        self, const unsigned char[:] message not None, flags=0
    ):
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._buffer.consume_outgoing(amt)
        self._socket.sendall(encrypted)

    def sendto(self, message, *args):
        if not 2 <= len(args) <= 3:
            raise TypeError("sendto() takes 2 or 3 arguments (%i given)"
                            % (1 + len(args)))
        if len(args) == 1:
            flags, address = 0, args[0]
        else:
            flags, address = args

        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        if flags:
            self._socket.sendto(encrypted, flags, address)
        else:
            self._socket.sendto(encrypted, address)
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

    def do_handshake(self):
        self._buffer._do_handshake_blocking(self._socket)

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
        with suppress(OSError):
            # shutdown may raise if the socket is not connected.
            self._socket.shutdown(_socket.SHUT_RDWR)
        return self._socket
