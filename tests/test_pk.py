"""Unit tests for mbedtls.pk."""

import numbers
import pickle
from functools import partial

import pytest  # type: ignore

from mbedtls import hashlib
from mbedtls.exceptions import TLSError  # type: ignore
from mbedtls.mpi import MPI  # type: ignore
from mbedtls.pk import (  # type: ignore
    ECC,
    RSA,
    Curve,
    DHClient,
    DHServer,
    ECDHClient,
    ECDHNaive,
    ECDHServer,
    ECPoint,
    _get_md_alg,
    _type_from_name,
    check_pair,
    get_supported_ciphers,
    get_supported_curves,
)


def test_supported_curves():
    assert sorted(get_supported_curves()) == [
        Curve.BRAINPOOLP256R1,
        Curve.BRAINPOOLP384R1,
        Curve.BRAINPOOLP512R1,
        Curve.SECP192K1,
        Curve.SECP192R1,
        Curve.SECP224K1,
        Curve.SECP224R1,
        Curve.SECP256K1,
        Curve.SECP256R1,
        Curve.SECP384R1,
        Curve.SECP521R1,
        Curve.CURVE25519,
        Curve.CURVE448,
    ]


def test_get_supported_ciphers():
    assert list(get_supported_ciphers()) == [
        b"NONE",
        b"RSA",
        b"EC",
        b"EC_DH",
        b"ECDSA",
    ]


@pytest.mark.parametrize(
    "md_algorithm",
    [vars(hashlib)[name] for name in hashlib.algorithms_available],
)
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), hashlib.Hash)


def test_rsa_encryp_decrypt(randbytes):
    rsa = RSA()
    rsa.generate(1024)
    msg = randbytes(rsa.key_size - 11)
    assert rsa.decrypt(rsa.encrypt(msg)) == msg


def do_generate(cipher):
    if isinstance(cipher, RSA):
        return cipher.generate(1024)
    if isinstance(cipher, ECC):
        return cipher.generate()
    assert 0


class TestECPoint:
    @pytest.fixture(params=[(MPI(1), MPI(2), MPI(3)), (1, 2, 3)])
    def xyz(self, request):
        return request.param

    @pytest.fixture
    def point(self, xyz):
        return ECPoint(*xyz)

    @pytest.mark.parametrize("repr_", (repr, str), ids=lambda f: f.__name__)
    def test_repr(self, repr_, point):
        assert isinstance(repr_(point), str)

    def test_pickle(self, point):
        assert point == pickle.loads(pickle.dumps(point))

    def test_hash(self, point):
        assert isinstance(hash(point), int)

    def test_accessors(self, point, xyz):
        x, y, z = xyz
        assert point.x == x
        assert point.y == y
        assert point.z == z

    def test_eq_point(self, point, xyz):
        assert (point == ECPoint(*xyz)) is True
        assert (point == ECPoint(0, 0, 0)) is False

    def test_eq_zero(self):
        zero = ECPoint(0, 0, 0)
        assert (zero == 1) is False
        assert (zero == 0) is True
        assert (zero == ECPoint(0, 0, 0)) is True

    def test_bool(self, point):
        assert bool(point) is True
        assert bool(ECPoint(0, 0, 0)) is False


class TestCipher:
    @pytest.fixture(
        params=[RSA]
        + [partial(ECC, curve) for curve in get_supported_curves()]
    )
    def cipher(self, request):
        return request.param()

    def test_pickle(self, cipher):
        assert cipher == pickle.loads(pickle.dumps(cipher))

    def test_hash(self, cipher):
        assert isinstance(hash(cipher), int)

    def test_type_accessor(self, cipher):
        assert cipher._type == _type_from_name(cipher.name)

        do_generate(cipher)

        assert cipher._type == _type_from_name(cipher.name)

    def test_export_private_key(self, cipher):
        assert cipher.export_key("DER") == b""
        assert cipher.export_key("PEM") == ""
        assert cipher.key_size == 0

        der = do_generate(cipher)

        assert der
        assert cipher.export_key() == der
        assert cipher.export_key("DER") == der
        assert cipher.export_key("PEM") != ""
        assert cipher == cipher.export_key("DER")
        assert cipher == cipher.export_key("PEM")
        assert type(cipher).from_DER(cipher.export_key("DER")) == cipher
        assert type(cipher).from_PEM(cipher.export_key("PEM")) == cipher
        assert cipher.key_size > 0

    def test_import_private_key(self, cipher):
        assert not cipher.export_key()
        assert not cipher.export_public_key()

        key = do_generate(cipher)

        other = type(cipher).from_buffer(key)
        assert other.export_key()
        assert other.export_public_key()
        assert check_pair(cipher, other) is True  # Test private half.
        assert check_pair(other, cipher) is True  # Test public half.
        assert check_pair(other, other) is True
        assert cipher == other

    def test_export_public_key(self, cipher):
        assert cipher.export_public_key("DER") == b""
        assert cipher.export_public_key("PEM") == ""

        der = do_generate(cipher)

        assert der
        assert type(cipher).from_DER(
            cipher.export_public_key("DER")
        ) == cipher.export_public_key("DER")
        assert type(cipher).from_PEM(
            cipher.export_public_key("PEM")
        ) == cipher.export_public_key("PEM")

    def test_import_public_key(self, cipher):
        assert not cipher.export_key()
        assert not cipher.export_public_key()

        do_generate(cipher)

        pub = cipher.export_public_key()
        other = type(cipher).from_buffer(pub)
        assert not other.export_key()
        assert other.export_public_key()
        assert check_pair(cipher, other) is False  # Test private half.
        assert check_pair(other, cipher) is True  # Test public half.
        assert check_pair(other, other) is False
        assert cipher != other

    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in hashlib.algorithms_guaranteed],
        ids=lambda dm: dm().name,
    )
    def test_sign_verify(self, cipher, digestmod, randbytes):
        msg = randbytes(4096)
        assert cipher.sign(msg, digestmod) is None

        do_generate(cipher)

        sig = cipher.sign(msg, digestmod)
        assert sig is not None
        assert cipher.verify(msg, sig, digestmod) is True
        assert cipher.verify(msg + b"\0", sig, digestmod) is False


class TestECCExportKey:
    @pytest.fixture(params=get_supported_curves())
    def curve(self, request):
        return request.param

    def test_export_private_key(self, curve):
        ecc = ECC(curve)
        assert ecc.export_key("NUM") == 0

        ecc.generate()
        assert ecc.export_key("NUM") != 0

    def test_export_public_key_to_point(self, curve):
        ecc = ECC(curve)
        assert ecc.export_public_key("POINT") == 0
        assert ecc.export_public_key("POINT") == ECPoint(0, 0, 0)

        ecc.generate()

        pub = ecc.export_public_key("POINT")
        assert isinstance(pub.x, numbers.Integral)
        assert isinstance(pub.y, numbers.Integral)
        assert isinstance(pub.z, numbers.Integral)
        assert pub.x not in (0, pub.y, pub.z)
        assert pub.y not in (0, pub.x, pub.z)
        assert pub.z in (0, 1)


class TestECCtoECDH:
    @pytest.mark.parametrize("curve", get_supported_curves())
    def test_exchange(self, curve):
        ecp = ECC(curve)
        ecp.generate()

        srv, cli = ecp.to_ECDH_server(), ecp.to_ECDH_client()

        cke = cli.generate()
        assert cli._has_public()

        srv.import_CKE(cke)
        assert srv._has_peers_public() is True

        srv_sec = srv.generate_secret()
        cli_sec = cli.generate_secret()
        assert srv_sec == cli_sec


class TestDH:
    @pytest.mark.parametrize("dh_cls", [DHServer, DHClient])
    def test_pickle(self, dh_cls):
        dhentity = dh_cls(MPI.prime(64), MPI.prime(20))

        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(dhentity)

        assert str(excinfo.value).startswith("cannot pickle")

    @pytest.mark.parametrize("dh_cls", [DHServer, DHClient])
    def test_accessors(self, dh_cls):
        modulus = MPI.prime(64)
        generator = MPI.prime(20)

        dhentity = dh_cls(modulus, generator)

        assert dhentity.modulus == modulus
        assert dhentity.generator == generator
        assert dhentity.key_size == 8
        assert dhentity.shared_secret == 0

    def test_exchange(self):
        cli = DHClient(MPI.prime(64), MPI.prime(20))
        srv = DHServer(MPI.prime(64), MPI.prime(20))

        ske = srv.generate()
        cli.import_SKE(ske)
        cke = cli.generate()
        srv.import_CKE(cke)

        srv_sec = srv.generate_secret()
        cli_sec = cli.generate_secret()
        assert srv_sec == cli_sec
        assert srv_sec == srv.shared_secret
        assert cli_sec == cli.shared_secret


class TestECDH:
    @pytest.fixture(params=get_supported_curves())
    def curve(self, request):
        return request.param

    @pytest.mark.parametrize("peer_cls", [ECDHServer, ECDHClient])
    def test_pickle(self, curve, peer_cls):
        peer = peer_cls(curve)

        with pytest.raises(TypeError) as excinfo:
            pickle.dumps(peer)

        assert str(excinfo.value).startswith("cannot pickle")

    @pytest.mark.parametrize("peer_cls", [ECDHServer, ECDHClient])
    def test_key_accessors_without_key(self, curve, peer_cls):
        peer = peer_cls(curve)

        assert not peer._has_private()
        assert not peer._has_public()
        assert not peer._has_peers_public()
        assert peer.private_key == 0
        assert peer.public_key == 0
        assert peer.peers_public_key == 0
        assert peer.shared_secret == 0

    def test_exchange(self, curve):
        srv, cli = ECDHServer(curve), ECDHClient(curve)

        ske = srv.generate()
        assert srv._has_public()

        cli.import_SKE(ske)
        assert cli._has_peers_public() is True

        cke = cli.generate()
        assert cli._has_public()

        srv.import_CKE(cke)
        assert srv._has_peers_public() is True

        srv_sec = srv.generate_secret()
        cli_sec = cli.generate_secret()
        assert srv_sec == srv.shared_secret
        assert cli_sec == cli.shared_secret
        assert srv_sec == cli_sec
        assert srv.shared_secret == cli.shared_secret

    def test_generate_public(self, curve):
        srv, cli = ECDHServer(curve), ECDHClient(curve)

        srv.generate()
        cli._private_key = srv.private_key
        assert cli.public_key != srv.public_key
        cli.generate_public_key()
        assert cli.public_key == srv.public_key


def do_exchange(alice, bob):
    alice_to_bob = alice.generate()
    bob_to_alice = bob.generate()
    alice.import_peers_public(bob_to_alice)
    bob.import_peers_public(alice_to_bob)
    alice.generate_secret()
    bob.generate_secret()


class TestECDHNaive:
    @pytest.fixture(params=[Curve.CURVE448, Curve.CURVE25519])
    def curve(self, request):
        return request.param

    def test_key_accessors_without_key(self, curve):
        peer = ECDHNaive(curve)

        assert not peer._has_private()
        assert not peer._has_public()
        assert peer.shared_secret == 0
        assert peer.private_key == 0
        assert peer.public_key == 0
        assert peer.peers_public_key == 0

    def test_exchange(self, curve):
        alice, bob = ECDHNaive(curve), ECDHNaive(curve)

        alice_to_bob = alice.generate()
        assert alice._has_public()

        bob_to_alice = bob.generate()
        assert bob._has_public()

        assert alice.private_key != 0
        assert bob.private_key != 0
        assert alice.private_key != bob.private_key

        assert alice.public_key != 0
        assert bob.public_key != 0
        assert alice.public_key != bob.public_key

        alice.import_peers_public(bob_to_alice)
        assert alice._has_peers_public() is True
        assert alice.peers_public_key == bob.public_key

        bob.import_peers_public(alice_to_bob)
        assert bob._has_peers_public() is True
        assert bob.peers_public_key == alice.public_key

        alice_secret = alice.generate_secret()
        bob_secret = bob.generate_secret()
        assert alice_secret == bob_secret
        assert alice_secret == alice.shared_secret
        assert bob_secret == bob.shared_secret

    def test_attacker_fails_with_public_keys(self, curve):
        alice, bob = ECDHNaive(curve), ECDHNaive(curve)
        do_exchange(alice, bob)

        eve = ECDHNaive(curve)
        eve._public_key = alice.public_key
        eve._peer_public_key = bob.public_key
        with pytest.raises(TLSError):
            eve.generate_secret()

    def test_attacker_succeeds_with_private_key(self, curve):
        alice, bob = ECDHNaive(curve), ECDHNaive(curve)
        do_exchange(alice, bob)

        eve = ECDHNaive(curve)
        eve._peer_public_key = bob.public_key
        eve._private_key = alice.private_key
        assert eve.generate_secret() == alice.shared_secret
