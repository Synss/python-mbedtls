import datetime as dt
import pickle
import socket
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest  # type: ignore

from mbedtls import hashlib
from mbedtls._tls import _DTLSCookie as DTLSCookie  # type: ignore
from mbedtls._tls import _PSKSToreProxy as PSKStoreProxy  # type: ignore
from mbedtls.pk import RSA
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


@pytest.fixture(scope="module")
def rootpath():
    return Path(__file__).parent.parent


def make_root_ca(
    subject=None,
    not_before=None,
    not_after=None,
    serial_number=None,
    basic_constraints=None,
    digestmod=None,
):
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
    issuer_crt,
    issuer_key,
    subject=None,
    not_before=None,
    not_after=None,
    serial_number=None,
    basic_constraints=None,
    digestmod=None,
):
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
    def test_picklable(self, obj):
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
    def test_unpicklable(self, obj):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(obj)

        assert str(excinfo.value).startswith("cannot pickle")


class TestPSKStoreProxy:
    @pytest.fixture()
    def psk_store(self):
        return {"client": b"the secret key"}

    @pytest.fixture()
    def proxy(self, psk_store):
        return PSKStoreProxy(psk_store)

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, psk_store):
        assert isinstance(repr_(psk_store), str)

    def test_unwrap(self, proxy, psk_store):
        assert proxy.unwrap() == psk_store

    def test_eq(self, proxy, psk_store):
        for k, v in psk_store.items():
            assert proxy[k] == v

    def test_len(self, proxy, psk_store):
        assert len(proxy) == len(psk_store)


class TestTLSVersion:
    @pytest.mark.parametrize("version", TLSVersion)
    def test_major(self, version):
        assert version.major() == 3

    def test_minor(self):
        # assert TLSVersion.SSLv3.minor() == 0
        assert TLSVersion.TLSv1.minor() == 1
        assert TLSVersion.TLSv1_1.minor() == 2
        assert TLSVersion.TLSv1_2.minor() == 3

    @pytest.mark.parametrize("version", TLSVersion)
    def test_from_major_minor(self, version):
        assert (
            TLSVersion.from_major_minor(version.major(), version.minor())
            is version
        )

    @pytest.mark.parametrize(
        "version", [TLSVersion.MINIMUM_SUPPORTED, TLSVersion.MAXIMUM_SUPPORTED]
    )
    def test_minmax_supported(self, version):
        assert version in TLSVersion


class TestDTLSVersion:
    @pytest.mark.parametrize("version", DTLSVersion)
    def test_major(self, version):
        assert version.major() == 3

    def test_minor(self):
        assert DTLSVersion.DTLSv1_0.minor() == 2
        assert DTLSVersion.DTLSv1_2.minor() == 3

    @pytest.mark.parametrize("version", DTLSVersion)
    def test_from_major_minor(self, version):
        assert (
            DTLSVersion.from_major_minor(version.major(), version.minor())
            is version
        )

    @pytest.mark.parametrize(
        "version",
        [DTLSVersion.MINIMUM_SUPPORTED, DTLSVersion.MAXIMUM_SUPPORTED],
    )
    def test_minmax_supported(self, version):
        assert version in DTLSVersion


class TestTLSRecordHeader:
    @pytest.fixture(params=TLSRecordHeader.RecordType)
    def record_type(self, request):
        return request.param

    @pytest.fixture(params=TLSVersion)
    def version(self, request):
        return request.param

    @pytest.fixture()
    def length(self):
        return 42

    @pytest.fixture()
    def header(self, record_type, version, length):
        return TLSRecordHeader(record_type, version, length)

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, record_type):
        assert isinstance(repr_(record_type), str)

    def test_hash(self, record_type):
        assert isinstance(hash(record_type), int)

    def test_accessors(self, header, record_type, version, length):
        assert len(header) == 5
        assert header.record_type is record_type
        assert header.version is version
        assert header.length == length

    def test_serialization(self, header):
        serialized = bytes(header)
        assert isinstance(serialized, bytes)
        assert len(serialized) == 5
        assert TLSRecordHeader.from_bytes(serialized) == header


class TestTLSSession:
    @pytest.fixture()
    def session(self):
        return TLSSession()

    def test_repr(self, session):
        assert isinstance(repr(session), str)


class TestTrustStore:
    @pytest.fixture()
    def store(self):
        return TrustStore.system()

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, store):
        assert isinstance(repr_(store), str)

    def test_eq(self, store):
        other = TrustStore(store)
        assert store is not other
        assert store == other

    def test_bool(self, store):
        assert not TrustStore()
        assert store

    def test_len(self, store):
        assert len(store) != 0

    def test_iter(self, store):
        assert store[0] != store[1]
        for n, crt in enumerate(store, start=1):
            assert crt in store
        assert n == len(store)

    def test_add_existing_certificate(self, store):
        length = len(store)
        store.add(store[0])
        assert len(store) == length

    def test_add_new_certificate(self, store):
        root_ca = make_root_ca()[0]
        length = len(store)
        store.add(root_ca)
        assert len(store) == length + 1


class TestDTLSCookie:
    @pytest.fixture()
    def cookie(self):
        return DTLSCookie()

    def test_generate_does_not_raise(self, cookie):
        cookie.generate()

    def test_timeout(self, cookie):
        assert cookie.timeout == 60
        cookie.timeout = 1000
        assert cookie.timeout == 1000


class TestConfiguration:
    @pytest.fixture(params=[DTLSConfiguration, TLSConfiguration])
    def conf(self, request):
        return request.param()

    @pytest.mark.parametrize("repr_", [repr, str], ids=lambda f: f.__name__)
    def test_repr(self, repr_, conf):
        assert isinstance(repr_(conf), str)

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf_ = conf.update(validate_certificates=validate)
        assert conf_.validate_certificates is validate

    @pytest.mark.parametrize("chain", [((), None), None])
    def test_set_certificate_chain(self, conf, chain):
        root_crt, root_key = make_root_ca()
        ee_crt, ee_key = make_crt(root_crt, root_key)
        if chain is None:
            chain = (ee_crt, root_crt), ee_key
        conf_ = conf.update(certificate_chain=chain)
        assert conf_.certificate_chain == chain

    def test_set_ciphers(self, conf):
        ciphers = tuple(ciphers_available())
        conf_ = conf.update(ciphers=ciphers)
        assert conf_.ciphers == ciphers

    @pytest.mark.parametrize(
        "inner_protocols",
        [[], (), [NextProtocol.H2, NextProtocol.H2C], [b"h2", b"h2c", b"ftp"]],
    )
    def test_set_inner_protocols(self, conf, inner_protocols):
        conf_ = conf.update(inner_protocols=inner_protocols)
        assert conf_.inner_protocols == tuple(
            NextProtocol(_) for _ in inner_protocols
        )

    @pytest.mark.parametrize("store", [TrustStore.system()])
    def test_trust_store(self, conf, store):
        conf_ = conf.update(trust_store=store)
        assert store
        assert conf_.trust_store == store

    @pytest.mark.parametrize("callback", [None])
    def test_set_sni_callback(self, conf, callback):
        assert conf.sni_callback is None

    @pytest.mark.parametrize("psk", [None, ("client", b"the secret key")])
    def test_psk(self, conf, psk):
        assert conf.pre_shared_key is None
        conf_ = conf.update(pre_shared_key=psk)
        assert conf_.pre_shared_key == psk

    @pytest.mark.parametrize(
        "psk_store", [None, {"client": b"the secret key"}]
    )
    def test_psk_store(self, conf, psk_store):
        assert conf.pre_shared_key_store is None
        conf_ = conf.update(pre_shared_key_store=psk_store)
        assert conf_.pre_shared_key_store == psk_store


class TestTLSConfiguration:
    @pytest.fixture()
    def conf(self):
        return TLSConfiguration()

    @pytest.mark.parametrize("version", TLSVersion)
    def test_lowest_supported_version(self, conf, version):
        conf_ = conf.update(lowest_supported_version=version)
        assert conf_.lowest_supported_version is version

    @pytest.mark.parametrize("version", TLSVersion)
    def test_highest_supported_version(self, conf, version):
        conf_ = conf.update(highest_supported_version=version)
        assert conf_.highest_supported_version is version


class TestDTLSConfiguration:
    @pytest.fixture()
    def conf(self):
        return DTLSConfiguration()

    @pytest.mark.parametrize("version", DTLSVersion)
    def test_lowest_supported_version(self, conf, version):
        conf_ = conf.update(lowest_supported_version=version)
        assert conf_.lowest_supported_version is version

    @pytest.mark.parametrize("version", DTLSVersion)
    def test_highest_supported_version(self, conf, version):
        conf_ = conf.update(highest_supported_version=version)
        assert conf_.highest_supported_version is version

    @pytest.mark.parametrize("anti_replay", [True, False])
    def test_set_anti_replay(self, conf, anti_replay):
        assert conf.anti_replay is True
        conf_ = conf.update(anti_replay=anti_replay)
        assert conf_.anti_replay is anti_replay

    @pytest.mark.parametrize(
        "hs_min_max", [(1, 60), (42, 69), (4.2, 6.9), (42.0, 69.0)]
    )
    def test_handshake_timeout_minmax(self, conf, hs_min_max):
        hs_min, hs_max = hs_min_max
        assert conf.handshake_timeout_min == 1.0
        assert conf.handshake_timeout_max == 60.0
        conf_ = conf.update(
            handshake_timeout_min=hs_min,
            handshake_timeout_max=hs_max,
        )
        assert conf_.handshake_timeout_min == hs_min
        assert conf_.handshake_timeout_max == hs_max

    @pytest.mark.parametrize(
        "hs_min_max", [(None, None), (1, None), (None, 60)]
    )
    def test_handshake_timeout_default(self, conf, hs_min_max):
        hs_min, hs_max = hs_min_max
        conf_ = conf.update(
            handshake_timeout_min=hs_min,
            handshake_timeout_max=hs_max,
        )
        assert conf_.handshake_timeout_min == hs_min or 1.0
        assert conf_.handshake_timeout_max == hs_max or 60.0


class TestBaseContext:
    @pytest.fixture(params=[Purpose.SERVER_AUTH, Purpose.CLIENT_AUTH])
    def purpose(self, request):
        return request.param

    @pytest.fixture(params=[TLSConfiguration, DTLSConfiguration])
    def conf(self, request):
        return request.param()

    @pytest.fixture(params=[ServerContext, ClientContext])
    def context(self, conf, request):
        cls = request.param
        return cls(conf)

    def test_repr(self, context):
        assert isinstance(repr(context), str)

    def test_get_configuration(self, context, conf):
        assert conf
        assert context.configuration is conf


class TestClientContext(TestBaseContext):
    @pytest.fixture(params=[None, "hostname", "localhost"])
    def hostname(self, request):
        return request.param

    @pytest.fixture()
    def context(self, conf, hostname):
        return ClientContext(conf)

    def test_context(self, context):
        assert isinstance(context, ClientContext)

    def test_hostname(self, context, hostname):
        wrapped_buffers = context.wrap_buffers(hostname)
        assert wrapped_buffers._server_hostname == hostname

    def test_wrap_buffers(self, context):
        assert isinstance(context.wrap_buffers(None), TLSWrappedBuffer)


class TestServerContext(TestBaseContext):
    @pytest.fixture()
    def context(self, conf):
        return ServerContext(conf)

    def test_context(self, context):
        assert isinstance(context, ServerContext)

    def test_wrap_buffers(self, context):
        assert isinstance(context.wrap_buffers(), TLSWrappedBuffer)


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


def make_server(conf):
    return ServerContext(conf).wrap_buffers()


def make_client(conf, hostname):
    return ClientContext(conf).wrap_buffers(hostname)


def do_io(*, src, dst, amt=1024):
    __tracebackhide__ = True
    assert src._output_buffer, "nothing to do"
    while src._output_buffer:
        in_transit = src.peek_outgoing(amt)
        src.consume_outgoing(len(in_transit))
        dst.receive_from_network(in_transit)


def do_send(data, *, src, dst):
    amt = src.write(data)
    do_io(src=src, dst=dst)
    return dst.read(amt)


def do_handshake(end, states):
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


def make_full_handshake(*, client, server):
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


def make_hello_verify_request(*, client, server, cookie):
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


def do_communicate(args):
    while True:
        with subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf8",
        ) as proc:
            out, err = proc.communicate()
            if "ConnectionRefusedError" not in err:
                return out
            time.sleep(0.01)  # Avoid tight CPU loop.
            continue


class TestTLSHandshake:
    @pytest.fixture(scope="class")
    def hostname(self):
        return "www.example.com"

    @pytest.fixture(scope="class")
    def certificate_chain(self, hostname):
        root_crt, root_key = make_root_ca()
        ee_crt, ee_key = make_crt(
            root_crt, root_key, subject=f"OU=test, CN={hostname}"
        )
        return (ee_crt, root_crt), ee_key

    def test_cert_without_validation(self, certificate_chain):
        server = make_server(
            TLSConfiguration(
                certificate_chain=certificate_chain,
                validate_certificates=False,
            )
        )
        client = make_client(
            TLSConfiguration(validate_certificates=False), "hostname"
        )
        make_full_handshake(client=client, server=server)

        secret = "a very secret message".encode("utf8")
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_cert_with_validation(self, hostname, certificate_chain):
        trust_store = TrustStore()
        for crt in certificate_chain[0][1:]:
            trust_store.add(crt)
        server = make_server(
            TLSConfiguration(
                certificate_chain=certificate_chain,
                validate_certificates=False,
            )
        )
        # Host name must now be the common name (CN) of the leaf certificate.
        client = make_client(
            TLSConfiguration(trust_store=trust_store), hostname
        )
        make_full_handshake(client=client, server=server)

        secret = "a very secret message".encode("utf8")
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_psk(self):
        psk = ("cli", b"secret")
        server = make_server(
            TLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        )
        client = make_client(
            TLSConfiguration(
                pre_shared_key=psk,
                validate_certificates=False,
            ),
            "hostname",
        )
        make_full_handshake(client=client, server=server)

        secret = "a very secret message".encode("utf8")
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret


class TestDTLSHandshake:
    def test_psk(self):
        psk = ("cli", b"secret")
        server = make_server(
            DTLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        )
        client = make_client(
            DTLSConfiguration(
                pre_shared_key=psk,
                validate_certificates=False,
            ),
            "hostname",
        )
        make_hello_verify_request(
            client=client, server=server, cookie="🍪🍪🍪".encode("utf-8")
        )
        make_full_handshake(client=client, server=server)

        secret = "a very secret message".encode("utf8")
        assert do_send(secret, src=client, dst=server) == secret
        assert do_send(secret, src=server, dst=client) == secret

    def test_resume_from_pickle(self):
        psk = ("cli", b"secret")
        server = make_server(
            DTLSConfiguration(
                pre_shared_key_store=dict((psk,)),
                validate_certificates=False,
            )
        )
        client = make_client(
            DTLSConfiguration(
                pre_shared_key=psk,
                ciphers=["TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256"],
                lowest_supported_version=DTLSVersion.DTLSv1_2,
                validate_certificates=False,
            ),
            "hostname",
        )
        make_hello_verify_request(
            client=client, server=server, cookie="🍪🍪🍪".encode("utf-8")
        )
        make_full_handshake(client=client, server=server)

        secret = "a very secret message".encode("utf8")
        do_send(secret, src=client, dst=server)
        do_send(secret, src=server, dst=client)

        client = pickle.loads(pickle.dumps(client))
        do_send(secret, src=client, dst=server)
        do_send(secret, src=server, dst=client)


@pytest.mark.skipif(sys.platform == "win32", reason="Flaky under Windows")
class TestProgramsTLS:
    @pytest.fixture()
    def port(self):
        """Return a free port

        Note:
            Not 100% race condition free.

        """
        port = 0
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("localhost", port))
            port = sock.getsockname()[1]
        return port

    @pytest.fixture()
    def server(self, rootpath, port):
        args = [
            sys.executable,
            str(rootpath / "programs" / "server.py"),
            "--port",
            f"{port}",
            "--tls",
            "--psk-store",
            "cli=secret",
        ]
        proc = subprocess.Popen(args, text=True, encoding="utf8")
        yield proc
        proc.kill()
        proc.wait(1.0)

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(10)
    def test_communicate(self, rootpath, port):
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


@pytest.mark.skipif(sys.platform == "win32", reason="Flaky under Windows")
class TestProgramsDTLS:
    @pytest.fixture()
    def port(self):
        """Return a free port

        Note:
            Not 100% race condition free.

        """
        port = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("localhost", port))
            port = sock.getsockname()[1]
        return port

    @pytest.fixture()
    def server(self, rootpath, port):
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

    @pytest.mark.usefixtures("server")
    @pytest.mark.timeout(10)
    def test_communication(self, rootpath, port):
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
