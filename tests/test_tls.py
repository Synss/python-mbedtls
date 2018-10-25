import datetime as dt
import multiprocessing as mp
import os
import socket
import struct
import sys
try:
    from contextlib import suppress
except ImportError:
    # Python 2.7
    from contextlib2 import suppress

import pytest

import mbedtls.hash as hashlib
from mbedtls.exceptions import TLSError
from mbedtls.pk import RSA, ECC
from mbedtls.x509 import BasicConstraints, CRT, CSR
from mbedtls.tls import *


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


def recvall(callback, amt):
    data = bytearray()
    while len(data) != amt:
        buffer = block(callback, amt - len(data))
        if not buffer:
            break
        data.extend(buffer)
    return bytes(data)


class Chain:
    @pytest.fixture(scope="class")
    def now(self):
        return dt.datetime.utcnow()

    @pytest.fixture(
        scope="class",
        params=[
            TLSVersion.SSLv3,
            TLSVersion.TLSv1,
            TLSVersion.TLSv1_1,
            TLSVersion.TLSv1_2,
        ])
    def version(self, request):
        return request.param

    @pytest.fixture(scope="class")
    def digestmod(self, version):
        return hashlib.sha256

    @pytest.fixture(scope="class")
    def ca0_key(self):
        ca0_key = RSA()
        ca0_key.generate()
        return ca0_key

    @pytest.fixture(scope="class")
    def ca1_key(self, version):
        if version < TLSVersion.TLSv1_1:
            ca1_key = RSA()
        else:
            ca1_key = ECC()
        ca1_key.generate()
        return ca1_key

    @pytest.fixture(scope="class")
    def ee0_key(self, version):
        if version < TLSVersion.TLSv1_1:
            ee0_key = RSA()
        else:
            ee0_key = ECC()
        ee0_key.generate()
        return ee0_key

    @pytest.fixture(scope="class")
    def ca0_crt(self, ca0_key, digestmod, now):
        ca0_csr = CSR.new(ca0_key, "CN=Trusted CA", digestmod())
        return CRT.selfsign(
            ca0_csr, ca0_key,
            not_before=now, not_after=now + dt.timedelta(days=90),
            serial_number=0x123456,
            basic_constraints=BasicConstraints(True, -1))

    @pytest.fixture(scope="class")
    def ca1_crt(self, ca1_key, ca0_crt, ca0_key, digestmod, now):
        ca1_csr = CSR.new(ca1_key, "CN=Intermediate CA", digestmod())
        return ca0_crt.sign(
            ca1_csr, ca0_key, now, now + dt.timedelta(days=90), 0x234567,
            basic_constraints=BasicConstraints(True, -1))

    @pytest.fixture(scope="class")
    def ee0_crt(self, ee0_key, ca1_crt, ca1_key, digestmod, now):
        ee0_csr = CSR.new(ee0_key, "CN=End Entity", digestmod())
        return ca1_crt.sign(
            ee0_csr, ca1_key, now, now + dt.timedelta(days=90), 0x345678)


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


class TestTLSConfiguration(Chain):

    @pytest.fixture
    def conf(self):
        return TLSConfiguration()

    @pytest.mark.parametrize("validate", [True, False])
    def test_set_validate_certificates(self, conf, validate):
        conf_ = conf.update(validate_certificates=validate)
        assert conf_.validate_certificates is validate

    @pytest.mark.parametrize("chain", [((), None), None])
    def test_set_certificate_chain(
            self, conf, chain, ee0_crt, ca1_crt, ee0_key):
        if chain is None:
            chain = (ee0_crt, ca1_crt), ee0_key
        conf_ = conf.update(certificate_chain=chain)
        assert conf_.certificate_chain == chain

    @pytest.mark.parametrize("ciphers", [ciphers_available()])
    def test_set_ciphers(self, conf, ciphers):
        conf_ = conf.update(ciphers=ciphers)
        assert conf_.ciphers == ciphers

    @pytest.mark.parametrize(
        "inner_protocols",
        [[], (), [NextProtocol.H2, NextProtocol.H2C],
         [b'h2', b'h2c', b'ftp']])
    def test_set_inner_protocols(self, conf, inner_protocols):
        conf_ = conf.update(inner_protocols=inner_protocols)
        assert conf_.inner_protocols == tuple(
            NextProtocol(_) for _ in inner_protocols)

    @pytest.mark.parametrize("version", TLSVersion)
    def test_lowest_supported_version(self, conf, version):
        conf_ = conf.update(lowest_supported_version=version)
        assert conf_.lowest_supported_version is version

    @pytest.mark.parametrize("version", TLSVersion)
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


class TestBaseContext:
    @pytest.fixture(params=[Purpose.SERVER_AUTH, Purpose.CLIENT_AUTH])
    def purpose(self, request):
        return request.param

    @pytest.fixture
    def conf(self, purpose):
        return TLSConfiguration()

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

    def test_negotiated_tls_version(self, context):
        assert context._negotiated_tls_version() is TLSVersion.SSLv3


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


class TestTLSCommunication(Chain):
    HEADER_FMT = "H"
    HEADER_SIZE = struct.calcsize(HEADER_FMT)
    CLOSE_MESSAGE = b"bye"

    @pytest.fixture(scope="class")
    def trust_store(self, ca0_crt, version):
        store = TrustStore()
        store.add(CRT.from_DER(ca0_crt.to_DER()))
        return store

    @pytest.fixture(scope="class")
    def srv_conf(
            self,
            version,
            ca0_crt, ca1_crt, ee0_crt, ee0_key,
            trust_store):
        return TLSConfiguration(
            trust_store=trust_store,
            certificate_chain=([ee0_crt, ca1_crt], ee0_key),
            lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            validate_certificates=False)

    def test_srv_conf(self, srv_conf, ca1_crt, ee0_crt, ee0_key, trust_store):
        assert srv_conf.trust_store == trust_store
        assert srv_conf.certificate_chain[0] == (ee0_crt, ca1_crt)
        assert srv_conf.certificate_chain[1] == ee0_key
        assert srv_conf.certificate_chain == ((ee0_crt, ca1_crt), ee0_key)

    @pytest.fixture(scope="class")
    def address(self):
        address = "/tmp/test.%i.%i.%i.sock" % sys.version_info[:3]
        with suppress(FileNotFoundError):
            os.unlink(address)
        return address

    @pytest.fixture
    def server(self, srv_conf, address, version):
        if version < TLSVersion.TLSv1:
            pytest.skip()
        ctx = ServerContext(srv_conf)
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sock.listen(1)

        def echo(sock):
            conn, addr = sock.accept()
            block(conn.do_handshake)
            while True:
                header = recvall(conn.recv, self.HEADER_SIZE)
                length = struct.unpack(self.HEADER_FMT, header)[0]
                data= recvall(conn.recv, length)
                if data == self.CLOSE_MESSAGE:
                    break
                conn.sendall(struct.pack(self.HEADER_FMT, length))
                conn.sendall(data)

        runner = mp.Process(target=echo, args=(sock, ))
        runner.start()
        yield sock
        runner.join(0.1)
        sock.close()
        runner.terminate()
        os.unlink(address)

    @pytest.fixture(scope="class")
    def cli_conf(self, version, trust_store):
        return TLSConfiguration(
            trust_store=trust_store,
            lowest_supported_version=TLSVersion.MINIMUM_SUPPORTED,
            highest_supported_version=version,
            validate_certificates=True)

    def test_cli_conf(self, cli_conf, trust_store):
        assert cli_conf.trust_store == trust_store
        assert cli_conf.validate_certificates == True

    @pytest.fixture
    def client(self, server, cli_conf, address):
        ctx = ClientContext(cli_conf)
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
            server_hostname="End Entity")
        sock.connect(address)
        block(sock.do_handshake)
        yield sock
        with suppress(Exception):
            block(sock.send,
                struct.pack(self.HEADER_FMT, len(self.CLOSE_MESSAGE)))
            block(sock.send, self.CLOSE_MESSAGE)
        sock.close()

    def test_server_hostname_fails_verification(
            self, server, cli_conf, address):
        ctx = ClientContext(cli_conf)
        sock = ctx.wrap_socket(
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
            server_hostname="Wrong End Entity")
        sock.connect(address)
        with pytest.raises(TLSError):
            block(sock.do_handshake)

    @pytest.fixture(params=[False])
    def buffer(self, request, randbytes):
        buffer = randbytes(5 * 16 * 1024)
        yield buffer
        if request.node.rep_call.failed and request.param:
            with open(
                "/tmp/dump.%s" % dt.datetime.utcnow().isoformat(),
                "wb",
            ) as dump:
                dump.write(buffer)

    @pytest.mark.parametrize("step", (10, 100, 1000, 10000, 16384 - 1, 16384))
    def test_client_server(self, client, buffer, step):
        received = bytearray()
        for idx in range(0, len(buffer), step):
            view = memoryview(buffer[idx:idx + step])
            # `length` must not be `step` if `idx + step` is larger
            # than the buffer.
            # 1. Send buffer.
            length = len(view)
            amt = block(client.send, struct.pack(self.HEADER_FMT, length))
            assert amt == self.HEADER_SIZE
            amt = block(client.send, view)
            assert amt == len(view)
            # 2. Get echo.
            header = recvall(client.recv, self.HEADER_SIZE)
            echo_length = struct.unpack(self.HEADER_FMT, header)[0]
            assert echo_length == length
            echo = recvall(client.recv, echo_length)
            assert echo == view
            received.extend(echo)
        assert received == buffer
