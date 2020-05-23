import datetime as dt
import multiprocessing as mp
import socket
import sys

import pytest

from mbedtls import hashlib
from mbedtls.exceptions import TLSError
from mbedtls.pk import RSA
from mbedtls.tls import *
from mbedtls.tls import _DTLSCookie as DTLSCookie
from mbedtls.x509 import CRT, CSR, BasicConstraints

try:
    from contextlib import suppress
except ImportError:
    # Python 2.7
    from contextlib2 import suppress


try:
    FileNotFoundError
except NameError:
    # Python 2.7
    FileNotFoundError = OSError


def block(callback, *args, **kwargs):
    counter = 0
    while True:
        with suppress(WantReadError, WantWriteError):
            return callback(*args, **kwargs)
        counter += 1
        if counter == sys.getrecursionlimit():
            raise RuntimeError("maximum recursion depth exceeded.")


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


class TestTrustStore(Chain):
    @pytest.fixture
    def store(self):
        return TrustStore.system()

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

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf_ = conf.update(validate_certificates=validate)
        assert conf_.validate_certificates is validate

    @pytest.mark.parametrize("chain", [((), None), None])
    def test_set_certificate_chain(
        self, conf, chain, ee0_crt, ca1_crt, ee0_key
    ):
        if chain is None:
            chain = (ee0_crt, ca1_crt), ee0_key
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


class _CommunicationBase(Chain):
    @pytest.fixture(scope="class")
    def proto(self):
        raise NotImplementedError

    @pytest.fixture(scope="class")
    def version(self):
        raise NotImplementedError

    @pytest.fixture(scope="class")
    def ciphers(self):
        return None

    @pytest.fixture(scope="class")
    def srv_hostname(self):
        return "End Entity"

    @pytest.fixture(scope="class")
    def cli_psk(self):
        return None

    @pytest.fixture(scope="class")
    def srv_psk(self):
        return None

    @pytest.fixture(scope="class")
    def srv_conf(self):
        raise NotImplementedError

    @pytest.fixture(scope="class")
    def cli_conf(self):
        raise NotImplementedError

    def echo(self, sock):
        raise NotImplementedError

    @pytest.fixture(params=[False])
    def buffer(self, request, randbytes):
        buffer = randbytes(5 * 16 * 1024)
        yield buffer
        if request.node.rep_call.failed and request.param:
            with open(
                "/tmp/dump.%s" % dt.datetime.utcnow().isoformat(), "wb"
            ) as dump:
                dump.write(buffer)

    @pytest.fixture(scope="class")
    def trust_store(self, ca0_crt):
        store = TrustStore()
        store.add(ca0_crt)
        return store

    @pytest.fixture
    def server(self, srv_conf, version, proto):
        ctx = ServerContext(srv_conf)
        sock = ctx.wrap_socket(socket.socket(socket.AF_INET, proto))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))
        if proto == socket.SOCK_STREAM:
            sock.listen(1)

        runner = mp.Process(target=self.echo, args=(sock,))
        runner.start()
        yield sock
        runner.terminate()
        runner.join()
        with suppress(OSError):
            sock.close()

    @pytest.fixture
    def client(self, server, srv_hostname, cli_conf, proto):
        ctx = ClientContext(cli_conf)
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_INET, proto), server_hostname=srv_hostname,
        )
        sock.connect(server.getsockname())
        yield sock
        with suppress(TLSError, OSError):
            sock.close()

    def test_srv_conf(
        self,
        srv_conf,
        trust_store,
        srv_psk,
        ciphers,
        ca1_crt,
        ee0_crt,
        ee0_key,
    ):
        assert srv_conf.trust_store == trust_store
        assert srv_conf.certificate_chain[0] == (ee0_crt, ca1_crt)
        assert srv_conf.certificate_chain[1] == ee0_key
        assert srv_conf.certificate_chain == ((ee0_crt, ca1_crt), ee0_key)
        if ciphers:
            assert srv_conf.ciphers == ciphers
        assert srv_conf.pre_shared_key_store == srv_psk

    def test_cli_conf(self, cli_conf, trust_store, cli_psk, ciphers):
        assert cli_conf.trust_store == trust_store
        assert cli_conf.validate_certificates == True
        if ciphers:
            assert cli_conf.ciphers == ciphers
        assert cli_conf.pre_shared_key == cli_psk


class _TLSCommunicationBase(_CommunicationBase):
    @pytest.fixture(scope="class")
    def proto(self):
        return socket.SOCK_STREAM

    @pytest.fixture(
        scope="class",
        params=[TLSVersion.TLSv1, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
    )
    def version(self, request):
        return request.param

    @pytest.fixture(scope="class")
    def srv_conf(
        self,
        version,
        trust_store,
        srv_psk,
        ciphers,
        ca0_crt,
        ca1_crt,
        ee0_crt,
        ee0_key,
    ):
        return TLSConfiguration(
            trust_store=trust_store,
            certificate_chain=([ee0_crt, ca1_crt], ee0_key),
            lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key_store=srv_psk,
            validate_certificates=False,
        )

    @pytest.fixture(scope="class")
    def cli_conf(self, version, trust_store, ciphers, cli_psk):
        return TLSConfiguration(
            trust_store=trust_store,
            lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key=cli_psk,
            validate_certificates=True,
        )

    def echo(self, sock):
        conn, addr = sock.accept()
        try:
            block(conn.do_handshake)
        except TLSError:
            conn.close()
            return
        while True:
            data = block(conn.recv, 2 << 13)
            amt = block(conn.send, data)
        conn.close()


class _DTLSCommunicationBase(_CommunicationBase):
    @pytest.fixture(scope="class")
    def proto(self):
        return socket.SOCK_DGRAM

    @pytest.fixture(scope="class", params=DTLSVersion)
    def version(self, request):
        return request.param

    @pytest.fixture(scope="class")
    def srv_conf(
        self,
        version,
        trust_store,
        srv_psk,
        ciphers,
        ca0_crt,
        ca1_crt,
        ee0_crt,
        ee0_key,
    ):
        return DTLSConfiguration(
            trust_store=trust_store,
            certificate_chain=([ee0_crt, ca1_crt], ee0_key),
            lowest_supported_version=DTLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key_store=srv_psk,
            validate_certificates=False,
        )

    @pytest.fixture(scope="class")
    def cli_conf(self, version, trust_store, cli_psk, ciphers):
        return DTLSConfiguration(
            trust_store=trust_store,
            lowest_supported_version=DTLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            ciphers=ciphers,
            pre_shared_key=cli_psk,
            validate_certificates=True,
        )

    def echo(self, sock):
        cli, addr = sock.accept()
        cli.setcookieparam(addr[0].encode("ascii"))
        with pytest.raises(HelloVerifyRequest):
            block(cli.do_handshake)

        _, (cli, addr) = cli, cli.accept()
        _.close()
        cli.setcookieparam(addr[0].encode("ascii"))
        try:
            block(cli.do_handshake)
        except TLSError:
            cli.close()
            return
        while True:
            data = block(cli.recv, 4096)
            # We must use `send()` instead of `sendto()` because the
            # DTLS socket is connected.
            amt = block(cli.send, data)
        cli.close()


class TestTLSHostNameVerificationFailure(_TLSCommunicationBase):
    @pytest.fixture(scope="class")
    def srv_hostname(self):
        return "Wrong End Entity"

    @pytest.mark.usefixtures("server")
    def test_handshake_raises_tlserror(self, client):
        with pytest.raises(TLSError):
            client.do_handshake()


class TestTLS_PSKAuthentication(_TLSCommunicationBase):
    @pytest.fixture(scope="class")
    def ciphers(self):
        return (
            "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
            "TLS-PSK-WITH-AES-256-CBC-SHA",
            "TLS-PSK-WITH-AES-128-CBC-SHA",
        )

    @pytest.fixture(scope="class")
    def srv_psk(self):
        return {"client": b"the secret key"}

    @pytest.fixture(scope="class")
    def cli_psk(self):
        return ("client", b"the secret key")

    @pytest.mark.usefixtures("server")
    def test_handshake_success(self, client):
        block(client.do_handshake)


class TestDTLS_PSKAuthentication(_DTLSCommunicationBase):
    @pytest.fixture(scope="class")
    def ciphers(self):
        return (
            "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
            "TLS-PSK-WITH-AES-256-CBC-SHA",
            "TLS-PSK-WITH-AES-128-CBC-SHA",
        )

    @pytest.fixture(scope="class")
    def srv_psk(self):
        return {"client": b"the secret key"}

    @pytest.fixture(scope="class")
    def cli_psk(self):
        return ("client", b"the secret key")

    @pytest.mark.usefixtures("server")
    def test_handshake_success(self, client):
        block(client.do_handshake)


class TestTLS_PSKAuthenticationFailure(_TLSCommunicationBase):
    @pytest.fixture(scope="class")
    def ciphers(self):
        return (
            "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
            "TLS-PSK-WITH-AES-256-CBC-SHA",
            "TLS-PSK-WITH-AES-128-CBC-SHA",
        )

    @pytest.fixture(
        scope="class",
        params=[
            {"client": b"another key"},
            {"another client": b"the secret key"},
            {"another client": b"another key"},
        ],
    )
    def srv_psk(self, request):
        return request.param

    @pytest.fixture(scope="class")
    def cli_psk(self):
        return ("client", b"the secret key")

    @pytest.mark.usefixtures("server")
    def test_handshake_raises_tlserror(self, client):
        with pytest.raises(TLSError):
            block(client.do_handshake)


class TestDTLS_PSKAuthenticationFailure(_DTLSCommunicationBase):
    @pytest.fixture(
        scope="class",
        params=[
            "TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
            "TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
            "TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
            "TLS-PSK-WITH-AES-256-CBC-SHA",
            "TLS-PSK-WITH-AES-128-CBC-SHA",
        ],
    )
    def ciphers(self, request):
        return (request.param,)

    @pytest.fixture(
        scope="class",
        params=[
            {"client": b"another key"},
            {"another client": b"the secret key"},
            {"another client": b"another key"},
        ],
    )
    def srv_psk(self, request):
        return request.param

    @pytest.fixture(scope="class")
    def cli_psk(self):
        return ("client", b"the secret key")

    @pytest.mark.usefixtures("server")
    def test_handshake_raises_tlserror(self, client):
        with pytest.raises(TLSError):
            block(client.do_handshake)


class TestTLSCommunication(_TLSCommunicationBase):
    @pytest.fixture(params=[100, 1000, 5000])
    def step(self, request):
        return request.param

    @pytest.mark.usefixtures("server")
    def test_client_server(self, client, buffer, step):
        block(client.do_handshake)
        received = bytearray()
        for idx in range(0, len(buffer), step):
            view = memoryview(buffer[idx : idx + step])
            amt = block(client.send, view)
            assert amt == len(view)
            assert block(client.recv, 2 << 13) == view


class TestDTLSCommunication(_DTLSCommunicationBase):
    @pytest.fixture(params=[10, 1000])
    def step(self, request):
        return request.param

    @pytest.mark.usefixtures("server")
    def test_client_server(self, client, buffer, step):
        block(client.do_handshake)
        received = bytearray()
        for idx in range(0, len(buffer), step):
            view = memoryview(buffer[idx : idx + step])
            amt = block(client.send, view)
            assert amt == len(view)
            assert block(client.recv, 2 << 13) == view
