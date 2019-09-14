"""Unit tests for mbedtls.pk."""

import numbers
from itertools import product
from functools import partial
from tempfile import TemporaryFile

import pytest

import mbedtls
import mbedtls.hash as _hash
from mbedtls.exceptions import *
from mbedtls.mpi import MPI
from mbedtls.pk import _type_from_name, _get_md_alg, CipherBase, ECPoint
from mbedtls.pk import *

try:
    long
except NameError:
    long = int


def test_supported_curves():
    assert get_supported_curves()


def test_get_supported_ciphers():
    assert get_supported_ciphers()


@pytest.mark.parametrize(
    "md_algorithm", [vars(_hash)[name] for name in _hash.algorithms_available]
)
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), _hash.Hash)


class TestECPoint:
    @pytest.fixture(params=[(MPI(1), MPI(2), MPI(3)), (1, 2, 3)])
    def xyz(self, request):
        return request.param

    @pytest.fixture
    def point(self, xyz):
        return ECPoint(*xyz)

    def test_accessors(self, point, xyz):
        x, y, z = xyz
        assert point.x == x
        assert point.y == y
        assert point.z == z

    def test_str(self, point):
        assert str(point) == "ECPoint(1, 2, 3)"

    def test_repr(self, point):
        assert repr(point) == "ECPoint(MPI(1), MPI(2), MPI(3))"

    def test_eq_point(self, point, xyz):
        assert (point == ECPoint(*xyz)) is True
        assert (point == ECPoint(0, 0, 0)) is False

    def test_eq_zero(self):
        zero = ECPoint(0, 0, 0)
        assert (zero == 1) is False
        assert (zero == 0) is True
        assert (zero == ECPoint(0, 0, 0)) is True

    def test_hash(self, point):
        zero = ECPoint(0, 0, 0)
        assert hash(zero) == hash(zero)
        assert hash(point) == hash(point)
        assert hash(zero) != hash(point)

    def test_bool(self, point):
        assert bool(point) is True
        assert bool(ECPoint(0, 0, 0)) is False


class _TestCipherBase:
    @pytest.fixture
    def cipher(self):
        raise NotImplementedError

    @pytest.fixture
    def key(self, cipher):
        raise NotImplementedError

    @pytest.fixture
    def pub(self, cipher, key):
        return type(cipher).from_buffer(cipher.export_public_key())

    @pytest.mark.usefixtures("key")
    def test_cmp_eq(self, cipher):
        assert cipher == cipher

    @pytest.mark.parametrize("format", ["DER", "PEM"])
    @pytest.mark.usefixtures("key")
    def test_cmp_eq_prv(self, cipher, format):
        assert cipher == cipher.export_key(format)

    @pytest.mark.parametrize("format", ["DER", "PEM"])
    def test_cmp_eq_pub(self, pub, format):
        assert pub == pub.export_public_key(format)

    @pytest.mark.parametrize("invalid", [b"", "", b"\1\2\3", "123"])
    @pytest.mark.usefixtures("key")
    def test_cmp_neq(self, cipher, invalid):
        assert cipher != invalid

    def test_export_key_without_key(self, cipher):
        assert cipher.export_key("DER") == b""
        assert cipher.export_key("PEM") == ""

    def test_export_public_key_without_key(self, cipher):
        assert cipher.export_public_key("DER") == b""
        assert cipher.export_public_key("PEM") == ""

    @pytest.mark.usefixtures("key")
    def test_export_key_to_PEM(self, cipher):
        der = cipher.export_key("DER")
        other = type(cipher).from_DER(der)
        assert der != b""
        assert cipher == other

    @pytest.mark.usefixtures("key")
    def test_export_key_to_DER(self, cipher):
        pem = cipher.export_key("PEM")
        other = type(cipher).from_PEM(pem)
        assert pem != ""
        assert cipher == other

    @pytest.mark.usefixtures("key")
    def test_export_public_key_to_DER(self, cipher):
        der = cipher.export_public_key("DER")
        other = type(cipher).from_DER(der)
        assert der != b""
        assert other == cipher.export_public_key("DER")

    @pytest.mark.usefixtures("key")
    def test_export_public_key_to_PEM(self, cipher):
        pem = cipher.export_public_key("PEM")
        other = type(cipher).from_PEM(pem)
        assert pem != ""
        assert other == cipher.export_public_key("PEM")

    def test_generate(self, cipher, key):
        assert cipher.export_key()
        assert cipher.export_key() == key
        assert cipher.export_public_key()

    @pytest.mark.usefixtures("key")
    def test_type_accessor(self, cipher):
        assert cipher._type == _type_from_name(cipher.name)

    def test_key_size_accessor(self, cipher):
        assert cipher.key_size == 0

    @pytest.mark.usefixtures("key")
    def test_key_size_accessor_with_key(self, cipher):
        assert cipher.key_size != 0

    @pytest.mark.usefixtures("key")
    def test_check_pair(self, cipher):
        assert check_pair(cipher, cipher) is True

    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name,
    )
    def test_sign_without_key_returns_none(self, cipher, digestmod, randbytes):
        message = randbytes(4096)
        assert cipher.sign(message, digestmod) is None

    @pytest.mark.usefixtures("key")
    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name,
    )
    def test_sign_verify(self, cipher, digestmod, randbytes):
        msg = randbytes(4096)
        sig = cipher.sign(msg, digestmod)
        assert sig is not None
        assert cipher.verify(msg, sig, digestmod) is True
        assert cipher.verify(msg + b"\0", sig, digestmod) is False

    @pytest.mark.usefixtures("key")
    def test_import_public_key(self, cipher):
        pub = cipher.export_public_key()
        other = type(cipher).from_buffer(pub)
        assert not other.export_key()
        assert other.export_public_key()
        assert check_pair(cipher, other) is False  # Test private half.
        assert check_pair(other, cipher) is True  # Test public half.
        assert check_pair(other, other) is False
        assert cipher != other

    def test_import_private_key(self, cipher, key):
        other = type(cipher).from_buffer(key)
        assert other.export_key()
        assert other.export_public_key()
        assert check_pair(cipher, other) is True  # Test private half.
        assert check_pair(other, cipher) is True  # Test public half.
        assert check_pair(other, other) is True
        assert cipher == other


@pytest.mark.skipif(
    not mbedtls.has_feature("rsa"), reason="requires RSA support in libmbedtls"
)
class TestRSA(_TestCipherBase):
    @pytest.fixture
    def cipher(self):
        return RSA()

    @pytest.fixture
    def key(self, cipher):
        key_size = 1024
        return cipher.generate(key_size)

    @pytest.mark.usefixtures("key")
    def test_encrypt_decrypt(self, cipher, randbytes):
        msg = randbytes(cipher.key_size - 11)
        assert cipher.decrypt(cipher.encrypt(msg)) == msg


class TestECC(_TestCipherBase):
    @pytest.fixture(autouse=True, params=get_supported_curves())
    def cipher(self, request):
        curve = request.param
        return ECC(curve)

    @pytest.fixture
    def key(self, cipher):
        return cipher.generate()

    def test_export_key_to_num_without_key(self, cipher):
        assert cipher.export_key("NUM") == 0

    @pytest.mark.usefixtures("key")
    def test_export_key_to_num_with_key(self, cipher):
        assert cipher.export_key("NUM") != 0

    def test_export_public_key_to_point_without_key(self, cipher):
        assert cipher.export_public_key("POINT") == 0
        assert cipher.export_public_key("POINT") == ECPoint(0, 0, 0)

    @pytest.mark.usefixtures("key")
    def test_public_value_accessor(self, cipher):
        pub = cipher.export_public_key("POINT")
        assert isinstance(pub.x, numbers.Integral)
        assert isinstance(pub.y, numbers.Integral)
        assert isinstance(pub.z, numbers.Integral)
        assert pub.x not in (0, pub.y, pub.z)
        assert pub.y not in (0, pub.x, pub.z)
        assert pub.z in (0, 1)

    @pytest.mark.usefixtures("key")
    def test_private_value_accessor(self, cipher):
        prv = cipher.export_key("NUM")
        assert isinstance(prv, numbers.Integral)
        assert prv != 0


class TestECCtoECDH:
    @pytest.fixture(params=get_supported_curves())
    def curve(self, request):
        return request.param

    @pytest.fixture
    def ecp(self, curve):
        ecp = ECC(curve)
        ecp.generate()
        return ecp

    @pytest.fixture
    def srv(self, ecp):
        return ecp.to_ECDH_server()

    @pytest.fixture
    def cli(self, ecp):
        return ecp.to_ECDH_client()

    def test_exchange(self, srv, cli):
        cke = cli.generate()
        assert cli._has_public()

        srv.import_CKE(cke)
        assert srv._has_peers_public() is True

        srv_sec = srv.generate_secret()
        cli_sec = cli.generate_secret()
        assert srv_sec == cli_sec


class _TestDHBase:
    @pytest.fixture
    def modulus_size(self):
        return 64

    @pytest.fixture
    def generator_size(self):
        return 20

    @pytest.fixture
    def modulus(self, modulus_size):
        return MPI.prime(modulus_size)

    @pytest.fixture
    def generator(self, generator_size):
        return MPI.prime(generator_size)

    @pytest.fixture
    def dhentity(self, modulus, generator):
        raise NotImplementedError

    def test_modulus(self, dhentity, modulus):
        assert dhentity.modulus == modulus

    def test_generator(self, dhentity, generator):
        assert dhentity.generator == generator

    def test_key_size_accessor(self, dhentity):
        assert dhentity.key_size == 8

    def test_share_secret_accessor_default(self, dhentity):
        assert dhentity.shared_secret == 0


class TestDHServer(_TestDHBase):
    @pytest.fixture
    def dhentity(self, modulus, generator):
        return DHServer(modulus, generator)


class TestDHClient(_TestDHBase):
    @pytest.fixture
    def dhentity(self, modulus, generator):
        return DHClient(modulus, generator)


class TestDHExchange:
    @pytest.fixture
    def modulus_size(self):
        return 64

    @pytest.fixture
    def generator_size(self):
        return 20

    @pytest.fixture
    def cli(self, modulus_size, generator_size):
        return DHClient(MPI.prime(modulus_size), MPI.prime(generator_size))

    @pytest.fixture
    def srv(self, modulus_size, generator_size):
        return DHServer(MPI.prime(modulus_size), MPI.prime(generator_size))

    def test_exchange(self, srv, cli):
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

    @pytest.fixture
    def srv(self, curve):
        return ECDHServer(curve)

    @pytest.fixture
    def cli(self, curve):
        return ECDHClient(curve)

    def test_srv_key_accessors_without_key(self, srv):
        assert not srv._has_private()
        assert not srv._has_public()
        assert not srv._has_peers_public()
        assert srv.private_key == 0
        assert srv.public_key == 0
        assert srv.peers_public_key == 0
        assert srv.shared_secret == 0

    def test_cli_key_accessors_without_key(self, cli):
        assert not cli._has_private()
        assert not cli._has_public()
        assert not cli._has_peers_public()
        assert cli.private_key == 0
        assert cli.public_key == 0
        assert cli.peers_public_key == 0
        assert cli.shared_secret == 0

    def test_exchange(self, srv, cli):
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

    def test_generate_public(self, srv, cli):
        srv.generate()
        cli._private_key = srv.private_key
        assert cli.public_key != srv.public_key
        cli.generate_public_key()
        assert cli.public_key == srv.public_key


class TestECDHNaive:
    @pytest.fixture(params=[Curve.CURVE448, Curve.CURVE25519])
    def curve(self, request):
        return request.param

    @pytest.fixture
    def alice(self, curve):
        return ECDHNaive(curve)

    @pytest.fixture
    def bob(self, curve):
        return ECDHNaive(curve)

    def test_key_accessors_without_key(self, alice, bob):
        for peer in (alice, bob):
            assert not peer._has_private()
            assert not peer._has_public()
            assert peer.shared_secret == 0
            assert peer.private_key == 0
            assert peer.public_key == 0
            assert peer.peers_public_key == 0

    def test_exchange(self, alice, bob):
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


class TestECDHNaiveAttacks:
    @pytest.fixture(params=[Curve.CURVE25519, Curve.CURVE448])
    def curve(self, request):
        return request.param

    @pytest.fixture
    def alice(self, curve):
        return ECDHNaive(curve)

    @pytest.fixture
    def bob(self, curve):
        return ECDHNaive(curve)

    @pytest.fixture
    def eve(self, curve):
        return ECDHNaive(curve)

    @pytest.fixture(autouse=True)
    def authenticate_alice_and_bob(self, alice, bob):
        alice_to_bob = alice.generate()
        bob_to_alice = bob.generate()
        alice.import_peers_public(bob_to_alice)
        bob.import_peers_public(alice_to_bob)
        alice_secret = alice.generate_secret()
        bob_secret = bob.generate_secret()

    def test_attacker_fails_with_public_keys(self, alice, bob, eve):
        eve._public_key = alice.public_key
        eve._peer_public_key = bob.public_key
        with pytest.raises(TLSError):
            eve.generate_secret()

    def test_attacker_succeeds_with_private_key(self, alice, bob, eve):
        eve._peer_public_key = bob.public_key
        eve._private_key = alice.private_key
        assert eve.generate_secret() == alice.shared_secret
