# SPDX-License-Identifier: MIT

from __future__ import annotations

import datetime as dt
import errno
import pickle
import socket
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import (
    Any,
    Callable,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import pytest

from mbedtls import hashlib
from mbedtls._tls import (
    _SUPPORTED_DTLS_VERSION,
    _SUPPORTED_TLS_VERSION,
    _dtls_from_version,
    _dtls_to_version,
)
from mbedtls._tls import _DTLSCookie as DTLSCookie  # type: ignore
from mbedtls._tls import _PSKSToreProxy as PSKStoreProxy  # type: ignore
from mbedtls._tls import _tls_from_version, _tls_to_version
from mbedtls.pk import ECC, RSA
from mbedtls.tls import (
    ClientContext,
    DTLSConfiguration,
    DTLSVersion,
    HandshakeStep,
    HelloVerifyRequest,
    NextProtocol,
    Purpose,
    ServerContext,
    TLSConfiguration,
    TLSRecordHeader,
    TLSSession,
    TLSVersion,
    TLSWrappedBuffer,
    TLSWrappedSocket,
    TrustStore,
    WantReadError,
    WantWriteError,
    ciphers_available,
)
from mbedtls.x509 import CRT, CSR, BasicConstraints

_Key = Union[RSA, ECC]
_HostName = str


@pytest.fixture(scope="module")
def rootpath() -> Path:
    return Path(__file__).parent.parent


def make_root_ca(
    subject: Optional[str] = None,
    not_before: Optional[dt.datetime] = None,
    not_after: Optional[dt.datetime] = None,
    serial_number: Optional[int] = None,
    basic_constraints: Optional[BasicConstraints] = None,
    digestmod: Optional[hashlib.Algorithm] = None,
) -> Tuple[CRT, _Key]:
    if subject is None:
        subject = "OU=test, CN=Trusted CA"
    if not_before is None:
        not_before = dt.datetime.utcnow()
    if not_after is None:
        not_after = not_before + dt.timedelta(days=90)
    if serial_number is None:
        serial_number = 0x123456
    if basic_constraints is None:
        basic_constraints = BasicConstraints(True, -1)
    if digestmod is None:
        digestmod = hashlib.sha256

    key = RSA()
    key.generate()
    crt = CRT.selfsign(
        csr=CSR.new(key, subject, digestmod()),
        issuer_key=key,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
        basic_constraints=basic_constraints,
    )
    return crt, key


def make_crt(
    issuer_crt: CRT,
    issuer_key: _Key,
    subject: Optional[str] = None,
    not_before: Optional[dt.datetime] = None,
    not_after: Optional[dt.datetime] = None,
    serial_number: Optional[int] = None,
    basic_constraints: Optional[BasicConstraints] = None,
    digestmod: Optional[hashlib.Algorithm] = None,
) -> Tuple[CRT, _Key]:
    if subject is None:
        subject = "OU=test, CN=hostname"
    if not_before is None:
        not_before = issuer_crt.not_before
    if not_after is None:
        not_after = issuer_crt.not_after
    if serial_number is None:
        serial_number = 0x123456
    if basic_constraints is None:
        basic_constraints = BasicConstraints()
    if digestmod is None:
        # TODO: issuer_crt.digestmod should work but doesn't.
        digestmod = hashlib.sha256

    key = RSA()
    key.generate()
    crt = issuer_crt.sign(
        csr=CSR.new(key, subject, digestmod()),
        issuer_key=issuer_key,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
        basic_constraints=basic_constraints,
    )
    return crt, key


class TestPickle:
    @pytest.mark.parametrize(
        "obj",
        [
            TLSConfiguration(),
            DTLSConfiguration(),
            ClientContext(TLSConfiguration()),
            ClientContext(DTLSConfiguration()),
            ServerContext(TLSConfiguration()),
            ServerContext(DTLSConfiguration()),
        ],
        ids=type,
    )
    def test_picklable(self, obj: object) -> None:
        assert obj == pickle.loads(pickle.dumps(obj))

    @pytest.mark.parametrize(
        "obj",
        [
            TLSSession(),
            TLSWrappedBuffer(ClientContext(DTLSConfiguration())),
            TLSWrappedBuffer(ClientContext(TLSConfiguration())),
            TLSWrappedBuffer(ServerContext(DTLSConfiguration())),
            TLSWrappedBuffer(ServerContext(TLSConfiguration())),
            TLSWrappedSocket(
                socket.socket(),
                TLSWrappedBuffer(ClientContext(DTLSConfiguration())),
            ),
            TLSWrappedSocket(
                socket.socket(),
                TLSWrappedBuffer(ClientContext(TLSConfiguration())),
            ),
            TLSWrappedSocket(
                socket.socket(),
                TLSWrappedBuffer(ServerContext(DTLSConfiguration())),
            ),
            TLSWrappedSocket(
                socket.socket(),
                TLSWrappedBuffer(ServerContext(TLSConfiguration())),
            ),
        ],
        ids=type,
    )
    def test_unpicklable(self, obj: object) -> None:
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(obj)

        assert str(excinfo.value).startswith("cannot pickle")


class TestPSKStoreProxy:
    @pytest.fixture()
    def psk_store(self) -> Mapping[str, bytes]:
        return {"client": b"the secret key"}

    @pytest.fixture()
    def proxy(self, psk_store: Mapping[str, bytes]) -> PSKStoreProxy:
        return PSKStoreProxy(psk_store)

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self, repr_: Callable[[object], str], psk_store: Mapping[str, bytes]
    ) -> None:
        assert isinstance(repr_(psk_store), str)

    def test_unwrap(
        self, proxy: PSKStoreProxy, psk_store: Mapping[str, bytes]
    ) -> None:
        assert proxy.unwrap() == psk_store

    def test_eq(
        self, proxy: PSKStoreProxy, psk_store: Mapping[str, bytes]
    ) -> None:
        for k, v in psk_store.items():
            assert proxy[k] == v

    def test_len(
        self, proxy: PSKStoreProxy, psk_store: Mapping[str, bytes]
    ) -> None:
        assert len(proxy) == len(psk_store)


class TestVersion:
    @pytest.mark.parametrize("version", _SUPPORTED_TLS_VERSION)
    def test_tls_enum_to_protocol_version(self, version: TLSVersion) -> None:
        assert _tls_to_version(_tls_from_version(version)) is version

    @pytest.mark.parametrize("version", _SUPPORTED_DTLS_VERSION)
    def test_dtls_enum_to_protocol_version(self, version: DTLSVersion) -> None:
        assert _dtls_to_version(_dtls_from_version(version)) is version


class TestTLSRecordHeader:
    @pytest.fixture(params=TLSRecordHeader.RecordType)
    def record_type(self, request: Any) -> TLSRecordHeader.RecordType:
        assert isinstance(request.param, TLSRecordHeader.RecordType)
        return request.param

    @pytest.fixture(params=_SUPPORTED_TLS_VERSION)
    def version(self, request: Any) -> TLSVersion:
        assert isinstance(request.param, TLSVersion)
        return request.param

    @pytest.fixture()
    def length(self) -> int:
        return 42

    @pytest.fixture()
    def header(
        self,
        record_type: TLSRecordHeader.RecordType,
        version: TLSVersion,
        length: int,
    ) -> TLSRecordHeader:
        return TLSRecordHeader(record_type, version, length)

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self,
        repr_: Callable[[object], str],
        record_type: TLSRecordHeader.RecordType,
    ) -> None:
        assert isinstance(repr_(record_type), str)

    def test_hash(self, record_type: TLSRecordHeader.RecordType) -> None:
        assert isinstance(hash(record_type), int)

    def test_accessors(
        self,
        header: TLSRecordHeader,
        record_type: TLSRecordHeader.RecordType,
        version: TLSVersion,
        length: int,
    ) -> None:
        assert len(header) == 5
        assert header.record_type is record_type
        assert header.version is version
        assert header.length == length

    def test_serialization(self, header: TLSRecordHeader) -> None:
        serialized = bytes(header)
        assert isinstance(serialized, bytes)
        assert len(serialized) == 5
        assert TLSRecordHeader.from_bytes(serialized) == header


class TestTLSSession:
    @pytest.fixture()
    def session(self) -> TLSSession:
        return TLSSession()

    def test_repr(self, session: TLSSession) -> None:
        assert isinstance(repr(session), str)


class TestTrustStore:
    @pytest.fixture()
    def store(self) -> TrustStore:
        return TrustStore.system()

    @pytest.mark.parametrize(
        "repr_",
        [repr, str],
        ids=lambda f: f.__name__,  # type: ignore[no-any-return]
    )
    def test_repr(
        self, repr_: Callable[[object], str], store: TrustStore
    ) -> None:
        assert isinstance(repr_(store), str)

    def test_eq(self, store: TrustStore) -> None:
        other = TrustStore(store)
        assert store is not other
        assert store == other

    def test_bool(self, store: TrustStore) -> None:
        assert not TrustStore()
        assert store

    def test_len(self, store: TrustStore) -> None:
        assert len(store) != 0

    def test_iter(self, store: TrustStore) -> None:
        assert store[0] != store[1]
        for n, crt in enumerate(store, start=1):
            assert crt in store
        assert n == len(store)

    def test_add_existing_certificate(self, store: TrustStore) -> None:
        length = len(store)
        store.add(store[0])
        assert len(store) == length

    def test_add_new_certificate(self, store: TrustStore) -> None:
        root_ca = make_root_ca()[0]
        length = len(store)
        store.add(root_ca)
        assert len(store) == length + 1


class TestDTLSCookie:
    @pytest.fixture()
    def cookie(self) -> DTLSCookie:
        return DTLSCookie()

    def test_generate_does_not_raise(self, cookie: DTLSCookie) -> None:
        cookie.generate()

    def test_timeout(self, cookie: DTLSCookie) -> None:
        assert cookie.timeout == 60
        cookie.timeout = 1000
        assert cookie.timeout == 1000


def assert_conf_invariant(
    conf: Union[TLSConfiguration, DTLSConfiguration],
    **elem: Any,
) -> None:
    # For the context, the configuration is converted into an
    # internal MbedTLSConfiguration and the accessors then
    # converts the MbedTLSConfiguration back into a
    # TLSConfiguration (or DTLSConfiguration).  These conversions
    # are what we actually check here.
    __tracebackhide__ = True
    assert len(elem) == 1

    key, value = next(iter(elem.items()))
    assert (
        getattr(ServerContext(conf.update(**elem)).configuration, key) == value
    )


class TestConfiguration:
    @pytest.fixture(params=[DTLSConfiguration, TLSConfiguration])
    def conf(self, request: Any) -> Union[TLSConfiguration, DTLSConfiguration]:
        conf = request.param()
        assert isinstance(conf, TLSConfiguration) or isinstance(
            conf, DTLSConfiguration
        )
        return conf

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(
        self, conf: Union[TLSConfiguration, DTLSConfiguration], validate: bool
    ) -> None:
        assert_conf_invariant(conf, validate_certificates=validate)

    def test_set_empty_certificate_chain(
        self, conf: Union[TLSConfiguration, DTLSConfiguration]
    ) -> None:
        assert_conf_invariant(conf, certificate_chain=None)

    def test_set_certificate_chain(
        self, conf: Union[TLSConfiguration, DTLSConfiguration]
    ) -> None:
        root_crt, root_key = make_root_ca()
        ee_crt, ee_key = make_crt(root_crt, root_key)
        chain = (ee_crt, root_crt), ee_key
        assert_conf_invariant(conf, certificate_chain=chain)

    def test_set_ciphers(
        self, conf: Union[TLSConfiguration, DTLSConfiguration]
    ) -> None:
        assert_conf_invariant(conf, ciphers=tuple(ciphers_available()))

    @pytest.mark.parametrize(
        "inner_protocols",
        [
            (),
            (NextProtocol.H2, NextProtocol.H2C),
            (NextProtocol.H2, NextProtocol.H2C, NextProtocol.FTP),
        ],
    )
    def test_set_inner_protocols(
        self,
        conf: Union[TLSConfiguration, DTLSConfiguration],
        inner_protocols: Tuple[Union[NextProtocol, bytes]],
    ) -> None:
        assert_conf_invariant(
            conf,
            inner_protocols=inner_protocols,
        )

    @pytest.mark.parametrize("trust_store", [TrustStore.system()])
    def test_trust_store(
        self,
        conf: Union[TLSConfiguration, DTLSConfiguration],
        trust_store: TrustStore,
    ) -> None:
        assert trust_store
        assert_conf_invariant(conf, trust_store=trust_store)

    @pytest.mark.parametrize("callback", [None])
    def test_set_sni_callback(
        self,
        conf: Union[TLSConfiguration, DTLSConfiguration],
        callback: object,
    ) -> None:
        assert conf.sni_callback is None

    @pytest.mark.parametrize("psk", [None, ("client", b"the secret key")])
    def test_psk(
        self,
        conf: Union[TLSConfiguration, DTLSConfiguration],
        psk: Tuple[str, bytes],
    ) -> None:
        assert conf.pre_shared_key is None
        assert_conf_invariant(conf, pre_shared_key=psk)

    @pytest.mark.parametrize("psk_store", [{}, {"client": b"the secret key"}])
    def test_psk_store(
        self,
        conf: Union[TLSConfiguration, DTLSConfiguration],
        psk_store: Mapping[str, bytes],
    ) -> None:
        assert not conf.pre_shared_key_store
        assert_conf_invariant(conf, pre_shared_key_store=psk_store)


class TestTLSConfiguration:
    @pytest.fixture()
    def conf(self) -> TLSConfiguration:
        return TLSConfiguration()

    def test_default_supported_versions(self, conf: TLSConfiguration) -> None:
        assert conf.lowest_supported_version is TLSVersion.TLSv1
        assert conf.highest_supported_version is TLSVersion.MAXIMUM_SUPPORTED

    @pytest.mark.parametrize("version", _SUPPORTED_TLS_VERSION)
    def test_lowest_supported_version(
        self, conf: TLSConfiguration, version: TLSVersion
    ) -> None:
        assert_conf_invariant(conf, lowest_supported_version=version)

    @pytest.mark.parametrize("version", _SUPPORTED_TLS_VERSION)
    def test_highest_supported_version(
        self, conf: TLSConfiguration, version: TLSVersion
    ) -> None:
        assert_conf_invariant(conf, highest_supported_version=version)


class TestDTLSConfiguration:
    @pytest.fixture()
    def conf(self) -> DTLSConfiguration:
        return DTLSConfiguration()

    def test_default_supported_versions(self, conf: DTLSConfiguration) -> None:
        assert conf.lowest_supported_version is DTLSVersion.DTLSv1_0
        assert conf.highest_supported_version is DTLSVersion.MAXIMUM_SUPPORTED

    @pytest.mark.parametrize("version", _SUPPORTED_DTLS_VERSION)
    def test_lowest_supported_version(
        self, conf: DTLSConfiguration, version: DTLSVersion
    ) -> None:
        assert_conf_invariant(conf, lowest_supported_version=version)

    @pytest.mark.parametrize("version", _SUPPORTED_DTLS_VERSION)
    def test_highest_supported_version(
        self, conf: DTLSConfiguration, version: DTLSVersion
    ) -> None:
        assert_conf_invariant(conf, highest_supported_version=version)

    @pytest.mark.parametrize("anti_replay", [True, False])
    def test_set_anti_replay(
        self, conf: DTLSConfiguration, anti_replay: bool
    ) -> None:
        assert conf.anti_replay is True
        assert_conf_invariant(conf, anti_replay=anti_replay)

    @pytest.mark.parametrize(
        "hs_min_max", [(1, 60), (42, 69), (4.2, 6.9), (42.0, 69.0)]
    )
    def test_handshake_timeout_minmax(
        self,
        conf: DTLSConfiguration,
        hs_min_max: Tuple[float, float],
    ) -> None:
        hs_min, hs_max = hs_min_max
        assert conf.handshake_timeout_min == 1.0
        assert conf.handshake_timeout_max == 60.0
        conf_ = conf.update(
            handshake_timeout_min=hs_min,
            handshake_timeout_max=hs_max,
        )
        assert conf_.handshake_timeout_min == hs_min
        assert conf_.handshake_timeout_max == hs_max

        assert_conf_invariant(conf, handshake_timeout_min=hs_min)
        assert_conf_invariant(conf, handshake_timeout_max=hs_max)

    @pytest.mark.parametrize("hs_min_max", [(1, 60), (42, 69), (4.2, 6.9)])
    def test_handshake_timeout_default(
        self,
        conf: DTLSConfiguration,
        hs_min_max: Tuple[float, float],
    ) -> None:
        assert conf.handshake_timeout_min == 1.0
        assert conf.handshake_timeout_max == 60.0

        hs_min, hs_max = hs_min_max
        conf_ = conf.update(
            handshake_timeout_min=hs_min,
            handshake_timeout_max=hs_max,
        )
        assert conf_.handshake_timeout_min == hs_min
        assert conf_.handshake_timeout_max == hs_max

        assert_conf_invariant(conf, handshake_timeout_min=hs_min)
        assert_conf_invariant(conf, handshake_timeout_max=hs_max)


class TestContext:
    @pytest.fixture(params=[Purpose.SERVER_AUTH, Purpose.CLIENT_AUTH])
    def purpose(self, request: Any) -> Purpose:
        assert isinstance(request.param, Purpose)
        return request.param

    @pytest.fixture(params=[TLSConfiguration, DTLSConfiguration])
    def conf(self, request: Any) -> Union[TLSConfiguration, DTLSConfiguration]:
        conf = request.param()
        assert isinstance(conf, TLSConfiguration) or isinstance(
            conf, DTLSConfiguration
        )
        return conf

    @pytest.fixture(params=[ServerContext, ClientContext])
    def context(
        self, conf: Union[TLSConfiguration, DTLSConfiguration], request: Any
    ) -> Union[ServerContext, ClientContext]:
        ctx = request.param(conf)
        assert isinstance(ctx, ServerContext) or isinstance(ctx, ClientContext)
        return ctx

    def test_repr(self, context: Union[ServerContext, ClientContext]) -> None:
        assert isinstance(repr(context), str)

    def test_get_configuration(
        self,
        context: Union[ServerContext, ClientContext],
        conf: Union[TLSConfiguration, DTLSConfiguration],
    ) -> None:
        assert context.configuration == conf


CLIENT_HELLO = (HandshakeStep.CLIENT_HELLO,)
SERVER_HELLO = (
    HandshakeStep.SERVER_HELLO,
    HandshakeStep.SERVER_CERTIFICATE,
    HandshakeStep.SERVER_KEY_EXCHANGE,
    HandshakeStep.CERTIFICATE_REQUEST,
    HandshakeStep.SERVER_HELLO_DONE,
)
CLIENT_KEY_EXCHANGE = (
    HandshakeStep.CLIENT_CERTIFICATE,
    HandshakeStep.CLIENT_KEY_EXCHANGE,
    HandshakeStep.CERTIFICATE_VERIFY,
    HandshakeStep.CLIENT_CHANGE_CIPHER_SPEC,
    HandshakeStep.CLIENT_FINISHED,
)
SERVER_CHANGE_CIPHER_SPEC = (
    HandshakeStep.SERVER_CHANGE_CIPHER_SPEC,
    HandshakeStep.SERVER_FINISHED,
)
HANDSHAKE_OVER = (
    HandshakeStep.FLUSH_BUFFERS,
    HandshakeStep.HANDSHAKE_WRAPUP,
    HandshakeStep.HANDSHAKE_OVER,
)


def do_io(
    *, src: TLSWrappedBuffer, dst: TLSWrappedBuffer, amt: int = 1024
) -> None:
    __tracebackhide__ = True
    assert src._output_buffer, "nothing to do"
    while src._output_buffer:
        in_transit = src.peek_outgoing(amt)
        src.consume_outgoing(len(in_transit))
        dst.receive_from_network(in_transit)


def do_send(
    data: bytes, *, src: TLSWrappedBuffer, dst: TLSWrappedBuffer
) -> bytes:
    amt = src.write(data)
    do_io(src=src, dst=dst)
    return dst.read(amt)


def do_handshake(
    end: TLSWrappedBuffer, states: Sequence[HandshakeStep]
) -> None:
    __tracebackhide__ = True
    while end._handshake_state is not states[0]:
        # The backend goes through every state for both
        # ends.  This is not relevant.
        try:
            end.do_handshake()
        except (WantReadError, WantWriteError) as exc:
            raise AssertionError(
                f"{type(end.context).__name__} wants {end._handshake_state}"
            ) from exc

    for state in states:
        assert end._handshake_state is state
        if state is HandshakeStep.HANDSHAKE_OVER:
            break
        with suppress(WantWriteError):
            end.do_handshake()


def make_full_handshake(
    *, client: TLSWrappedBuffer, server: TLSWrappedBuffer
) -> None:
    do_handshake(client, CLIENT_HELLO)
    do_io(src=client, dst=server)

    do_handshake(server, SERVER_HELLO)
    do_io(src=server, dst=client)
    assert client.negotiated_protocol() == server.negotiated_protocol()

    do_handshake(client, CLIENT_KEY_EXCHANGE)
    do_io(src=client, dst=server)
    assert client.negotiated_tls_version() == server.negotiated_tls_version()

    do_handshake(server, SERVER_CHANGE_CIPHER_SPEC)
    do_io(src=server, dst=client)

    do_handshake(server, HANDSHAKE_OVER)
    do_handshake(client, HANDSHAKE_OVER)
    assert client.cipher() == server.cipher()


def make_hello_verify_request(
    *, client: TLSWrappedBuffer, server: TLSWrappedBuffer, cookie: bytes
) -> None:
    do_handshake(client, CLIENT_HELLO)
    do_io(src=client, dst=server)
    server.setcookieparam(cookie)
    with pytest.raises(HelloVerifyRequest):
        do_handshake(
            server,
            (
                HandshakeStep.SERVER_HELLO,
                HandshakeStep.SERVER_HELLO_VERIFY_REQUEST_SENT,
            ),
        )

    do_handshake(server, (HandshakeStep.HELLO_REQUEST,))
    server.setcookieparam(cookie)
    do_io(src=server, dst=client)


def do_communicate(args: Any) -> str:
    while True:
        with subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf8",
        ) as proc:
            out, err = proc.communicate()
            if "ConnectionRefusedError" in err:
                time.sleep(0.01)  # Avoid tight CPU loop.
                continue
            return out


class TestTLSHandshake:
    @pytest.fixture(scope="class")
    def hostname(self) -> _HostName:
        return "www.example.com"

    @pytest.fixture(scope="class")
    def certificate_chain(
        self, hostname: _HostName
    ) -> Tuple[Tuple[CRT, ...], _Key]:
        root_crt, root_key = make_root_ca()
        ee_crt, ee_key = make_crt(
            root_crt, root_key, subject=f"OU=test, CN={hostname}"
        )
        return (ee_crt, root_crt), ee_key

    def test_cert_without_validation(
        self, certificate_chain: Tuple[Tuple[CRT, ...], _Key]
    ) -> None:
        server = ServerContext(
            TLSConfiguration(
                certificate_chain=certificate_chain,
                validate_certificates=False,
            )
        ).wrap_buffers()
        client = ClientContext(
            TLSConfiguration(validate_certificates=False)
        ).wrap_buffers("hostname")
        make_full_handshake(client=client, server=server)

        secret = b"a very secret message"
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_cert_with_validation(
        self,
        hostname: _HostName,
        certificate_chain: Tuple[Tuple[CRT, ...], _Key],
    ) -> None:
        trust_store = TrustStore()
        crt: CRT
        for crt in certificate_chain[0][1:]:
            trust_store.add(crt)
        server = ServerContext(
            TLSConfiguration(
                certificate_chain=certificate_chain,
                validate_certificates=False,
            )
        ).wrap_buffers()
        # Host name must now be the common name (CN) of the leaf certificate.
        client = ClientContext(
            TLSConfiguration(trust_store=trust_store)
        ).wrap_buffers(hostname)
        make_full_handshake(client=client, server=server)

        secret = b"a very secret message"
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_psk(self) -> None:
        psk = ("cli", b"secret")
        server = ServerContext(
            TLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        ).wrap_buffers()
        client = ClientContext(
            TLSConfiguration(
                pre_shared_key=psk,
                validate_certificates=False,
            ),
        ).wrap_buffers("hostname")
        make_full_handshake(client=client, server=server)

        secret = b"a very secret message"
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret


class TestDTLSHandshake:
    def test_psk(self) -> None:
        psk = ("cli", b"secret")
        server = ServerContext(
            DTLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        ).wrap_buffers()
        client = ClientContext(
            DTLSConfiguration(
                pre_shared_key=psk,
                validate_certificates=False,
            ),
        ).wrap_buffers("hostname")
        make_hello_verify_request(
            client=client, server=server, cookie="🍪🍪🍪".encode()
        )
        make_full_handshake(client=client, server=server)

        secret = b"a very secret message"
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_resume_from_pickle(self) -> None:
        psk = ("cli", b"secret")
        server = ServerContext(
            DTLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        ).wrap_buffers()
        client = ClientContext(
            DTLSConfiguration(
                pre_shared_key=psk,
                ciphers=("TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256",),
                lowest_supported_version=DTLSVersion.DTLSv1_2,
                validate_certificates=False,
            ),
        ).wrap_buffers("hostname")
        make_hello_verify_request(
            client=client, server=server, cookie="🍪🍪🍪".encode()
        )
        make_full_handshake(client=client, server=server)

        secret = b"a very secret message"
        do_send(secret, src=client, dst=server)
        do_send(secret, src=server, dst=client)

        client = pickle.loads(pickle.dumps(client))
        do_send(secret, src=client, dst=server)
        do_send(secret, src=server, dst=client)


@pytest.mark.skipif(sys.platform == "win32", reason="Flaky under Windows")
class TestProgramsTLS:
    @pytest.fixture(scope="class")
    def port(self) -> int:
        """Return a free port

        Note:
            Not 100% race condition free.

        """
        port = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("localhost", port))
            port = sock.getsockname()[1]
        return port

    @pytest.fixture(scope="class")
    def server(
        self, rootpath: Path, port: int
    ) -> Iterator[subprocess.Popen[str]]:
        args = [
            sys.executable,
            str(rootpath / "programs" / "server.py"),
            "--port",
            f"{port}",
            "--tls",
            "--psk-store",
            "cli=secret",
        ]
        with subprocess.Popen(args, text=True, encoding="utf8") as proc:
            yield proc
            proc.kill()
            proc.wait(1.0)

    @pytest.mark.repeat(3)
    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_client(self, rootpath: Path, port: int) -> None:
        secret = "a very secret message"
        args = [
            sys.executable,
            str(rootpath / "programs" / "client.py"),
            "--port",
            f"{port}",
            "--tls",
            "--psk",
            "cli=secret",
            secret,
        ]
        for _ in range(3):
            assert do_communicate(args) == secret + "\n"

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_send_recv(self, port: int) -> None:
        secret = b"a very secret message"
        with ClientContext(
            TLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), "localhost"
        ) as client:
            client.connect(("127.0.0.1", port))
            client.do_handshake()
            sent = client.send(secret)
            assert sent == len(secret)

            data = client.recv(1024)
        assert data == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_send_recv_into(self, port: int) -> None:
        secret = b"a very secret message"
        buffer = bytearray(b"\0" * 256)
        with ClientContext(
            TLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), "localhost"
        ) as client:
            client.connect(("127.0.0.1", port))
            client.do_handshake()
            sent = client.send(secret)
            assert sent == len(secret)

            received = client.recv_into(buffer, 1024)
        assert buffer[:received] == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_sendall_recv(self, port: int) -> None:
        secret = b"a very secret message"
        with ClientContext(
            TLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), "localhost"
        ) as client:
            client.connect(("127.0.0.1", port))
            client.do_handshake()
            client.sendall(secret)
            data = client.recv(1024)
        assert data == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_connectionless_unavailable(self, port: int) -> None:
        address = ("127.0.0.1", port)
        with ClientContext(
            TLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), "localhost"
        ) as client:
            with pytest.raises(OSError) as excinfo:
                client.do_handshake(address)

        assert excinfo.value.errno is errno.ENOTCONN


@pytest.mark.skipif(sys.platform == "win32", reason="Flaky under Windows")
class TestProgramsDTLS:
    @pytest.fixture(scope="class")
    def port(self) -> int:
        """Return a free port

        Note:
            Not 100% race condition free.

        """
        port = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("localhost", port))
            port = sock.getsockname()[1]
        return port

    @pytest.fixture(scope="class")
    def server(
        self, rootpath: Path, port: int
    ) -> Iterator[subprocess.Popen[str]]:
        args = [
            sys.executable,
            str(rootpath / "programs" / "server.py"),
            "--port",
            f"{port}",
            "--dtls",
            "--psk-store",
            "cli=secret",
        ]
        proc = subprocess.Popen(args, text=True, encoding="utf8")
        yield proc
        proc.kill()
        proc.wait(1.0)

    @pytest.mark.timeout(3)
    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_client(self, rootpath: Path, port: int) -> None:
        secret = "a very secret message"
        args = [
            sys.executable,
            str(rootpath / "programs" / "client.py"),
            "--port",
            f"{port}",
            "--dtls",
            "--psk",
            "cli=secret",
            secret,
        ]
        for _ in range(3):
            assert do_communicate(args) == secret + "\n"

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_send_recv(self, port: int) -> None:
        address = ("127.0.0.1", port)
        secret = b"a very secret message"
        with ClientContext(
            DTLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "localhost"
        ) as client:
            client.connect(address)
            client.do_handshake()
            sent = client.send(secret)
            assert sent == len(secret)

            data = client.recv(1024)
        assert data == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_sendto_recvfrom(self, port: int) -> None:
        address = ("127.0.0.1", port)
        secret = b"a very secret message"
        with ClientContext(
            DTLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "localhost"
        ) as client:
            client.do_handshake(address)
            sent = client.sendto(secret, address)
            assert sent == len(secret)

            data, addr = client.recvfrom(1024)
            assert addr == address
        assert data == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_sendto_recvfrom_with_flags(self, port: int) -> None:
        # Note that flags is always 0 (noop) here because we are only
        # interested in testing the API.  See also issue #62.
        address = ("127.0.0.1", port)
        secret = b"a very secret message"
        with ClientContext(
            DTLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "localhost"
        ) as client:
            client.do_handshake(0, address)
            sent = client.sendto(secret, 0, address)
            assert sent == len(secret)

            data, addr = client.recvfrom(1024, 0)
            assert addr == address
        assert data == secret

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(2)
    def test_raw_socket_sendto_recvfrom_into(self, port: int) -> None:
        address = ("127.0.0.1", port)
        secret = b"a very secret message"
        buffer = bytearray(b"\0" * 256)
        with ClientContext(
            DTLSConfiguration(
                pre_shared_key=("cli", b"secret"),
                validate_certificates=False,
            ),
        ).wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM), "localhost"
        ) as client:
            client.do_handshake(address)
            sent = client.sendto(secret, address)
            assert sent == len(secret)

            received, addr = client.recvfrom_into(buffer, 1024)
            assert addr == address
        assert buffer[:received] == secret
