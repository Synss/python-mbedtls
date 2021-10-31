import datetime as dt
import itertools
import multiprocessing as mp
import pickle
import platform
import select
import socket
import sys
import time
from contextlib import suppress

import pytest

from mbedtls import hashlib
from mbedtls.exceptions import TLSError
from mbedtls.pk import RSA
from mbedtls.tls import *
from mbedtls.tls import TLSSession
from mbedtls.tls import _BaseConfiguration as BaseConfiguration
from mbedtls.tls import _DTLSCookie as DTLSCookie
from mbedtls.tls import _enable_debug_output
from mbedtls.tls import _PSKSToreProxy as PSKStoreProxy
from mbedtls.tls import _set_debug_level
from mbedtls.x509 import CRT, CSR, BasicConstraints


class Client:
    def __init__(self, cli_conf, proto, srv_address, srv_hostname):
        super().__init__()
        self.cli_conf = cli_conf
        self.proto = proto
        self.srv_address = srv_address
        self.srv_hostname = srv_hostname
        self._sock = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()

    def __del__(self):
        self.stop()

    @property
    def context(self):
        if self._sock is None:
            return None
        return self._sock.context

    def do_handshake(self):
        if not self._sock:
            return

        self._sock.do_handshake()

    def echo(self, buffer, chunksize):
        if not self._sock:
            return

        view = memoryview(buffer)
        received = bytearray()
        for idx in range(0, len(view), chunksize):
            part = view[idx : idx + chunksize]
            amt = self._sock.send(part)
            received += self._sock.recv(2 << 13)
        return received

    def start(self):
        if self._sock:
            self.stop()

        self._sock = ClientContext(self.cli_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto),
            server_hostname=self.srv_hostname,
        )
        self._sock.connect(self.srv_address)

    def stop(self):
        if not self._sock:
            return

        with suppress(TLSError, OSError):
            self._sock.close()
        self._sock = None

    def restart(self):
        self.stop()
        self.start()


class Server:
    def __init__(self, srv_conf, proto, conn_q):
        super().__init__()
        self.srv_conf = srv_conf
        self.proto = proto
        self.conn_q = conn_q
        self._sock = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()

    def __del__(self):
        self.stop()

    @property
    def context(self):
        if self._sock is None:
            return None
        return self._sock.context

    def start(self):
        if self._sock:
            self.stop()

        self._sock = ServerContext(self.srv_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto)
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(
            ("127.0.0.1" if platform.system() == "Windows" else "", 0)
        )
        if self.proto == socket.SOCK_STREAM:
            self._sock.listen(1)
        self.conn_q.put(self._sock.getsockname())

    def stop(self):
        if not self._sock:
            return

        with suppress(TLSError, OSError):
            self._sock.close()
        self._sock = None

    def run(self, conn_handler):
        with self:
            {
                TLSConfiguration: self._run_tls,
                DTLSConfiguration: self._run_dtls,
            }[type(self.srv_conf)](conn_handler)

    def _run_tls(self, conn_handler):
        assert self._sock
        conn, addr = self._sock.accept()
        try:
            conn.do_handshake()
        except TLSError:
            conn.close()
            return
        try:
            conn_handler(conn)
        finally:
            conn.close()

    def _run_dtls(self, conn_handler):
        assert self._sock
        cli, addr = self._sock.accept()
        cli.setcookieparam(addr[0].encode("ascii"))
        with pytest.raises(HelloVerifyRequest):
            cli.do_handshake()

        _, (cli, addr) = cli, cli.accept()
        _.close()
        cli.setcookieparam(addr[0].encode("ascii"))
        try:
            cli.do_handshake()
        except TLSError:
            cli.close()
            return
        try:
            conn_handler(cli)
        finally:
            cli.close()


class EchoHandler:
    def __init__(self, stop_ev, packet_size=4096):
        self.stop_ev = stop_ev
        self.packet_size = packet_size

    def __call__(self, conn):
        while not self.stop_ev.is_set():
            readable, _, err = select.select([conn], [], [], 0.1)
            if err:
                break

            for _ in readable:
                # We use `send()` instead of `sendto()` for DTLS as well
                # because the DTLS socket is connected.
                received = conn.recv(self.packet_size)
                sent = conn.send(received)


class TestPickle:
    @pytest.fixture
    def session(self):
        return TLSSession()

    @pytest.fixture(params=[TLSConfiguration, DTLSConfiguration])
    def conf(self, request):
        return request.param()

    @pytest.fixture(params=[ClientContext, ServerContext])
    def context(self, request, conf):
        return request.param(conf)

    @pytest.fixture
    def identity(self):
        return lambda obj: pickle.loads(pickle.dumps(obj))

    @pytest.fixture
    def tls_wrapped_buffer(self, context):
        return TLSWrappedBuffer(context)

    @pytest.fixture
    def tls_wrapped_socket(self, tls_wrapped_buffer):
        return TLSWrappedSocket(socket.socket(), tls_wrapped_buffer)

    def test_session(self, session):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(session)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_configuration(self, conf, identity):
        assert conf == identity(conf)

    def test_context(self, context, identity):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(context)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_tls_wrapped_buffer(self, tls_wrapped_buffer):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(tls_wrapped_buffer)

        assert str(excinfo.value).startswith("cannot pickle")

    def test_tls_wrapped_socket(self, tls_wrapped_socket):
        # Python socket.socket is not pickable.
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(tls_wrapped_socket)

        assert str(excinfo.value).startswith("cannot pickle")


class TestPSKStoreProxy:
    @pytest.fixture
    def psk_store(self):
        return {"client": b"the secret key"}

    @pytest.fixture
    def proxy(self, psk_store):
        return PSKStoreProxy(psk_store)

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
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

    @pytest.fixture
    def length(self):
        return 42

    @pytest.fixture
    def header(self, record_type, version, length):
        return TLSRecordHeader(record_type, version, length)

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
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
    @pytest.fixture
    def session(self):
        return TLSSession()

    def test_repr(self, session):
        assert isinstance(repr(session), str)


class Chain:
    @pytest.fixture(scope="class")
    def now(self):
        return dt.datetime.utcnow()

    @pytest.fixture(scope="class")
    def digestmod(self):
        return hashlib.sha256

    @pytest.fixture(scope="class")
    def ca0_key(self):
        ca0_key = RSA()
        ca0_key.generate()
        return ca0_key

    @pytest.fixture(scope="class")
    def ca1_key(self):
        ca1_key = RSA()
        ca1_key.generate()
        return ca1_key

    @pytest.fixture(scope="class")
    def ee0_key(self):
        ee0_key = RSA()
        ee0_key.generate()
        return ee0_key

    @pytest.fixture(scope="class")
    def ca0_crt(self, ca0_key, digestmod, now):
        ca0_csr = CSR.new(ca0_key, "CN=Trusted CA", digestmod())
        return CRT.selfsign(
            ca0_csr,
            ca0_key,
            not_before=now,
            not_after=now + dt.timedelta(days=90),
            serial_number=0x123456,
            basic_constraints=BasicConstraints(True, -1),
        )

    @pytest.fixture(scope="class")
    def ca1_crt(self, ca1_key, ca0_crt, ca0_key, digestmod, now):
        ca1_csr = CSR.new(ca1_key, "CN=Intermediate CA", digestmod())
        return ca0_crt.sign(
            ca1_csr,
            ca0_key,
            now,
            now + dt.timedelta(days=90),
            0x234567,
            basic_constraints=BasicConstraints(True, -1),
        )

    @pytest.fixture(scope="class")
    def ee0_crt(self, ee0_key, ca1_crt, ca1_key, digestmod, now):
        ee0_csr = CSR.new(ee0_key, "CN=End Entity", digestmod())
        return ca1_crt.sign(
            ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x345678
        )

    @pytest.fixture(scope="class")
    def certificate_chain(self, ee0_crt, ca1_crt, ee0_key):
        return (ee0_crt, ca1_crt), ee0_key


class TestTrustStore(Chain):
    @pytest.fixture
    def store(self):
        return TrustStore.system()

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
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

    def test_add_new_certificate(self, store, ca0_crt):
        length = len(store)
        store.add(ca0_crt)
        assert len(store) == length + 1


class TestDTLSCookie:
    @pytest.fixture
    def cookie(self):
        return DTLSCookie()

    def test_generate_does_not_raise(self, cookie):
        cookie.generate()

    def test_timeout(self, cookie):
        assert cookie.timeout == 60
        cookie.timeout = 1000
        assert cookie.timeout == 1000


class _BaseConfiguration(Chain):
    @pytest.fixture
    def conf(self):
        raise NotImplementedError

    @pytest.fixture
    def version(self):
        raise NotImplementedError

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
    def test_repr(self, repr_, conf):
        assert isinstance(repr_(conf), str)

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf_ = conf.update(validate_certificates=validate)
        assert conf_.validate_certificates is validate

    @pytest.mark.parametrize("chain", [((), None), None])
    def test_set_certificate_chain(self, conf, chain, certificate_chain):
        if chain is None:
            chain = certificate_chain
        conf_ = conf.update(certificate_chain=chain)
        assert conf_.certificate_chain == chain

    @pytest.mark.parametrize("ciphers", (ciphers_available(),))
    def test_set_ciphers(self, conf, ciphers):
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

    def test_lowest_supported_version(self, conf, version):
        conf_ = conf.update(lowest_supported_version=version)
        assert conf_.lowest_supported_version is version

    def test_highest_supported_version(self, conf, version):
        conf_ = conf.update(highest_supported_version=version)
        assert conf_.highest_supported_version is version

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


class TestTLSConfiguration(_BaseConfiguration):
    @pytest.fixture
    def conf(self):
        return TLSConfiguration()

    @pytest.fixture(params=TLSVersion)
    def version(self, request):
        return request.param


class TestDTLSConfiguration(_BaseConfiguration):
    @pytest.fixture
    def conf(self):
        return DTLSConfiguration()

    @pytest.fixture(params=DTLSVersion)
    def version(self, request):
        return request.param

    @pytest.mark.parametrize("anti_replay", [True, False])
    def test_set_anti_replay(self, conf, anti_replay):
        assert conf.anti_replay is True
        conf_ = conf.update(anti_replay=anti_replay)
        assert conf_.anti_replay is anti_replay

    @pytest.mark.parametrize(
        "hs_min, hs_max", [(1, 60), (42, 69), (4.2, 6.9), (42.0, 69.0)]
    )
    def test_handshake_timeout_minmax(self, conf, hs_min, hs_max):
        assert conf.handshake_timeout_min == 1.0
        assert conf.handshake_timeout_max == 60.0
        conf_ = conf.update(
            handshake_timeout_min=hs_min,
            handshake_timeout_max=hs_max,
        )
        assert conf_.handshake_timeout_min == hs_min
        assert conf_.handshake_timeout_max == hs_max

    @pytest.mark.parametrize(
        "hs_min, hs_max", [(None, None), (1, None), (None, 60)]
    )
    def test_handshake_timeout_default(self, conf, hs_min, hs_max):
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

    def test_selected_npn_protocol(self, context):
        assert context._selected_npn_protocol() is None

    def test_cipher(self, context):
        assert context._cipher() is None

    def test_get_channel_binding(self, context):
        assert context._get_channel_binding() is None

    # def test_negotiated_tls_version(self, context):
    #     assert context._negotiated_tls_version() is TLSVersion.SSLv3

    @pytest.fixture
    def tls_wrapped_buffer(self, context):
        return TLSWrappedBuffer(context)

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
    def test_repr_tls_wrapped_buffer(self, repr_, tls_wrapped_buffer):
        assert isinstance(repr_(tls_wrapped_buffer), str)


class TestClientContext(TestBaseContext):
    @pytest.fixture(params=[None, "hostname", "localhost"])
    def hostname(self, request):
        return request.param

    @pytest.fixture
    def context(self, conf, hostname):
        return ClientContext(conf)

    def test_context(self, context):
        assert isinstance(context, ClientContext)

    def test_hostname(self, context, hostname):
        _ = context.wrap_buffers(hostname)
        assert context._hostname == hostname

    def test_wrap_buffers(self, context):
        assert isinstance(context.wrap_buffers(None), TLSWrappedBuffer)


class TestServerContext(TestBaseContext):
    @pytest.fixture
    def context(self, conf):
        return ServerContext(conf)

    def test_context(self, context):
        assert isinstance(context, ServerContext)

    def test_wrap_buffers(self, context):
        assert isinstance(context.wrap_buffers(), TLSWrappedBuffer)


PSK_AUTHENTICATION_CIPHERS = (
    "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
    "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
    "TLS-DHE-PSK-WITH-AES-256-CBC-SHA",
    "TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
    "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
    "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
    "TLS-PSK-WITH-AES-256-CBC-SHA",
    "TLS-PSK-WITH-AES-128-CBC-SHA",
)


def generate_configs(*configs):
    for conf, versions in configs:
        for version in versions:
            yield conf, version


class TestCommunication(Chain):
    @pytest.fixture(
        params=generate_configs(
            (TLSConfiguration, TLSVersion), (DTLSConfiguration, DTLSVersion)
        )
    )
    def configs(self, request):
        return request.param

    @pytest.fixture
    def conf_cls(self, configs):
        assert issubclass(configs[0], BaseConfiguration)
        return configs[0]

    @pytest.fixture
    def version(self, configs):
        assert isinstance(configs[1], (TLSVersion, DTLSVersion))
        return configs[1]

    @pytest.fixture
    def version_min(self, conf_cls):
        return {
            TLSConfiguration: TLSVersion.MINIMUM_SUPPORTED,
            DTLSConfiguration: DTLSVersion.MINIMUM_SUPPORTED,
        }[conf_cls]

    @pytest.fixture
    def proto(self, conf_cls):
        return {
            TLSConfiguration: socket.SOCK_STREAM,
            DTLSConfiguration: socket.SOCK_DGRAM,
        }[conf_cls]

    @pytest.fixture
    def srv_conf(
        self,
        conf_cls,
        version,
        version_min,
        trust_store,
        certificate_chain,
        srv_psk,
        ciphers,
    ):
        return conf_cls(
            trust_store=trust_store,
            certificate_chain=certificate_chain,
            lowest_supported_version=version_min,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key_store=srv_psk,
            validate_certificates=False,
        )

    @pytest.fixture
    def cli_conf(
        self, conf_cls, version, version_min, trust_store, cli_psk, ciphers
    ):
        return conf_cls(
            trust_store=trust_store,
            lowest_supported_version=version_min,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key=cli_psk,
            validate_certificates=True,
        )

    @pytest.fixture(params=[4])
    def debug(self, srv_conf, cli_conf, request):
        _enable_debug_output(srv_conf)
        _enable_debug_output(cli_conf)
        _set_debug_level(request.param)

    @pytest.fixture(scope="class", params=[None])
    def ciphers(self, request):
        return request.param

    @pytest.fixture(scope="class", params=["End Entity"])
    def srv_hostname(self, request):
        return request.param

    @pytest.fixture(scope="class", params=[None])
    def cli_psk(self, request):
        return request.param

    @pytest.fixture(scope="class", params=[None])
    def srv_psk(self, request):
        return request.param

    @pytest.fixture(params=[False])
    def buffer(self, request, randbytes):
        return randbytes(5 * 16 * 1024)

    @pytest.fixture(scope="class")
    def trust_store(self, ca0_crt):
        store = TrustStore()
        store.add(ca0_crt)
        return store

    @pytest.fixture
    def server(self, srv_conf, version, proto):
        conn_q = mp.SimpleQueue()
        stop_ev = mp.Event()
        srv = Server(srv_conf, proto, conn_q)
        runner = mp.Process(target=srv.run, args=(EchoHandler(stop_ev),))

        runner.start()
        yield conn_q.get()
        stop_ev.set()
        runner.join()

    @pytest.fixture
    def client(self, server, srv_hostname, cli_conf, proto):
        return Client(cli_conf, proto, server, srv_hostname)

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures("server")
    @pytest.mark.parametrize(
        "srv_hostname", ["Wrong End Entity"], indirect=True
    )
    def test_host_name_verification_failure(self, client, srv_hostname):
        with pytest.raises(TLSError), client:
            client.do_handshake()

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures("server")
    @pytest.mark.parametrize(
        "ciphers", [PSK_AUTHENTICATION_CIPHERS], indirect=True
    )
    @pytest.mark.parametrize(
        "srv_psk", [{"client": b"the secret key"}], indirect=True
    )
    @pytest.mark.parametrize(
        "cli_psk", [("client", b"the secret key")], indirect=True
    )
    @pytest.mark.parametrize("chunksize", [1024])
    def test_psk_authentication_success(self, client, buffer, chunksize):
        with client:
            client.do_handshake()
            assert client.echo(buffer, chunksize) == buffer

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures("server")
    @pytest.mark.parametrize(
        "ciphers", [PSK_AUTHENTICATION_CIPHERS], indirect=True
    )
    @pytest.mark.parametrize(
        "srv_psk",
        [
            {"client": b"another key"},
            {"another client": b"the secret key"},
            {"another client": b"another key"},
        ],
        indirect=True,
    )
    @pytest.mark.parametrize(
        "cli_psk", [("client", b"the secret key")], indirect=True
    )
    def test_psk_authentication_failure(self, client):
        with pytest.raises(TLSError), client:
            client.do_handshake()

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures("server")
    @pytest.mark.parametrize("ciphers", (ciphers_available(),), indirect=True)
    @pytest.mark.parametrize("chunksize", [1024])
    def test_client_server(self, client, buffer, chunksize):
        with client:
            while True:
                try:
                    client.do_handshake()
                except (WantReadError, WantWriteError):
                    pass
                except TLSError:
                    client.restart()
                else:
                    break

            assert client.echo(buffer, chunksize) == buffer

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures("server")
    @pytest.mark.parametrize("ciphers", (ciphers_available(),), indirect=True)
    def test_session_caching(self, client, cli_conf):
        session = TLSSession()
        with client:
            while True:
                try:
                    client.do_handshake()
                except (WantReadError, WantWriteError):
                    pass
                except (ConnectionError, TLSError):
                    client.restart()
                else:
                    break

            session.save(client.context)

        new_context = session.resume(cli_conf)
        assert isinstance(new_context, ClientContext)
        assert new_context._verified
