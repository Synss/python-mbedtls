import datetime as dt
import pickle
import socket

import pytest

from mbedtls import hashlib
from mbedtls._tls import _DTLSCookie as DTLSCookie
from mbedtls._tls import _PSKSToreProxy as PSKStoreProxy
from mbedtls.pk import RSA
from mbedtls.tls import *
from mbedtls.tls import TLSSession
from mbedtls.x509 import CRT, CSR, BasicConstraints


class TestPickle:
    @pytest.mark.parametrize(
        "obj", (TLSConfiguration(), DTLSConfiguration()), ids=type
    )
    def test_picklable(self, obj):
        assert obj == pickle.loads(pickle.dumps(obj))

    @pytest.mark.parametrize(
        "obj",
        (
            ClientContext(TLSConfiguration()),
            ClientContext(DTLSConfiguration()),
            ServerContext(TLSConfiguration()),
            ServerContext(DTLSConfiguration()),
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
        ),
        ids=type,
    )
    def test_unpicklable(self, obj):
        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(obj)

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
