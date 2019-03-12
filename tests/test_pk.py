"""Unit tests for mbedtls.pk."""

import numbers
from itertools import product
from functools import partial
from tempfile import TemporaryFile

import pytest

import mbedtls.hash as _hash
from mbedtls.exceptions import *
from mbedtls.mpi import MPI
from mbedtls.pk import _type_from_name, _get_md_alg, CipherBase
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
    "md_algorithm", [vars(_hash)[name] for name in _hash.algorithms_available])
def test_digestmod_from_ctor(md_algorithm):
    assert callable(md_algorithm)
    algorithm = _get_md_alg(md_algorithm)
    assert isinstance(algorithm(), _hash.Hash)


class _TestCipherBase(object):

    @pytest.fixture
    def key(self):
        raise NotImplementedError

    @pytest.fixture
    def pub(self, key):
        return type(self.cipher).from_buffer(
            self.cipher.export_public_key())

    @pytest.mark.usefixtures("key")
    def test_cmp_eq(self):
        assert self.cipher == self.cipher

    @pytest.mark.parametrize("format", ["DER", "PEM"])
    @pytest.mark.usefixtures("key")
    def test_cmp_eq_prv(self, format):
        assert self.cipher == self.cipher.export_key(format)

    @pytest.mark.parametrize("format", ["DER", "PEM"])
    def test_cmp_eq_pub(self, pub, format):
        assert pub == pub.export_public_key(format)

    @pytest.mark.parametrize("invalid", [b"", "", b"\1\2\3", "123"])
    @pytest.mark.userfixtures("key")
    def test_cmp_neq(self, invalid):
        assert self.cipher != invalid

    def test_key_accessors_without_key(self):
        assert not self.cipher.export_key()
        assert not self.cipher.export_public_key()

    def test_generate(self, key):
        assert self.cipher.export_key()
        assert self.cipher.export_key() == key
        assert self.cipher.export_public_key()

    @pytest.mark.usefixtures("key")
    def test_type_accessor(self):
        assert self.cipher._type == _type_from_name(self.cipher.name)

    def test_key_size_accessor(self):
        assert self.cipher.key_size == 0

    @pytest.mark.usefixtures("key")
    def test_key_size_accessor_with_key(self):
        assert self.cipher.key_size != 0

    @pytest.mark.usefixtures("key")
    def test_check_pair(self):
        assert check_pair(self.cipher, self.cipher) is True

    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name)
    def test_sign_without_key_returns_none(self, digestmod, randbytes):
        message = randbytes(4096)
        assert self.cipher.sign(message, digestmod) is None

    @pytest.mark.usefixtures("key")
    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in _hash.algorithms_guaranteed],
        ids=lambda dm: dm().name)
    def test_sign_verify(self, digestmod, randbytes):
        msg = randbytes(4096)
        sig = self.cipher.sign(msg, digestmod)
        assert sig is not None
        assert self.cipher.verify(msg, sig, digestmod) is True
        assert self.cipher.verify(msg + b"\0", sig, digestmod) is False

    @pytest.mark.usefixtures("key")
    def test_import_public_key(self):
        pub = self.cipher.export_public_key()
        other = type(self.cipher).from_buffer(pub)
        assert not other.export_key()
        assert other.export_public_key()
        assert check_pair(self.cipher, other) is False  # Test private half.
        assert check_pair(other, self.cipher) is True  # Test public half.
        assert check_pair(other, other) is False
        assert self.cipher != other

    def test_import_private_key(self, key):
        other = type(self.cipher).from_buffer(key)
        assert other.export_key()
        assert other.export_public_key()
        assert check_pair(self.cipher, other) is True  # Test private half.
        assert check_pair(other, self.cipher) is True  # Test public half.
        assert check_pair(other, other) is True
        assert self.cipher == other

    @pytest.mark.usefixtures("key")
    def test_export_to_PEM(self):
        prv = self.cipher.export_key(format="PEM")
        other = type(self.cipher).from_PEM(prv)
        assert self.cipher == other


class TestRSA(_TestCipherBase):

    @pytest.fixture(autouse=True)
    def rsa(self):
        self.cipher = RSA()
        yield
        self.cipher = None

    @pytest.fixture
    def key(self):
        key_size = 1024
        return self.cipher.generate(key_size)

    @pytest.mark.usefixtures("key")
    def test_encrypt_decrypt(self, randbytes):
        msg = randbytes(self.cipher.key_size - 11)
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg

    @pytest.mark.userfixtures("key")
    def test_ecc_from_rsa_raises_valueerror(self):
        with pytest.raises(ValueError):
            ECC.from_buffer(self.cipher.export_key("DER"))


class TestECC(_TestCipherBase):

    @pytest.fixture(autouse=True, params=get_supported_curves())
    def ecp(self, request):
        curve = request.param
        self.cipher = ECC(curve)
        yield
        self.cipher = None

    @pytest.fixture
    def key(self):
        return self.cipher.generate()

    def test_cipher_without_key(self):
        assert self.cipher.export_key("NUM") == 0
        assert self.cipher.export_public_key("POINT") == 0
        assert self.cipher.export_public_key("POINT") == (0, 0)

    @pytest.mark.usefixtures("key")
    def test_public_value_accessor(self):
        pub = self.cipher.export_public_key("POINT")
        assert isinstance(pub.x, numbers.Integral)
        assert isinstance(pub.y, numbers.Integral)
        assert isinstance(pub.z, numbers.Integral)
        assert pub.x not in (0, pub.y, pub.z)
        assert pub.y not in (0, pub.x, pub.z)
        assert pub.z in (0, 1)

    @pytest.mark.usefixtures("key")
    def test_private_value_accessor(self):
        prv = self.cipher.export_key("NUM")
        assert isinstance(prv, numbers.Integral)
        assert prv != 0

    @pytest.mark.userfixtures("key")
    def test_rsa_from_ecc_raises_valueerror(self):
        with pytest.raises(ValueError):
            RSA.from_buffer(self.cipher.export_key("DER"))


class TestECCtoECDH:

    @pytest.fixture(autouse=True, params=get_supported_curves())
    def _setup(self, request):
        curve = request.param
        ecp = ECC(curve)
        ecp.generate()
        self.srv = ecp.to_ECDH_server()
        self.cli = ecp.to_ECDH_client()

    def test_exchange(self):
        cke = self.cli.generate()
        assert self.cli._has_public()

        self.srv.import_CKE(cke)
        assert self.srv._has_peers_public() is True

        srv_sec = self.srv.generate_secret()
        cli_sec = self.cli.generate_secret()
        assert srv_sec == cli_sec


class TestDH:
    @pytest.fixture
    def modulus_size(self):
        return 64

    @pytest.fixture
    def generator_size(self):
        return 20

    @pytest.fixture
    def srv_modulus(self, modulus_size):
        return MPI.prime(modulus_size)

    @pytest.fixture
    def srv_generator(self, generator_size):
        return MPI.prime(generator_size)

    @pytest.fixture
    def cli_modulus(self, modulus_size):
        return MPI.prime(modulus_size)

    @pytest.fixture
    def cli_generator(self, generator_size):
        return MPI.prime(generator_size)

    @pytest.fixture
    def srv(self, srv_modulus, srv_generator):
        return DHServer(srv_modulus, srv_generator)

    @pytest.fixture
    def cli(self, cli_modulus, cli_generator):
        return DHClient(cli_modulus, cli_generator)

    def test_srv_modulus(self, srv):
        assert srv.modulus.is_prime()

    def test_srv_generator(self, srv):
        assert srv.generator.is_prime()

    def test_srv_modulus_accessor(self, srv, srv_modulus):
        assert srv.modulus == srv_modulus

    def test_srv_generator_accessor(self, srv, srv_generator):
        assert srv.generator == srv_generator

    def test_srv_key_size_accessor(self, srv):
        assert srv.key_size == 8

    def test_cli_modulus(self, cli):
        assert cli.modulus.is_prime()

    def test_cli_generator(self, cli):
        assert cli.generator.is_prime()

    def test_cli_modulus_accessor(self, cli, cli_modulus):
        assert cli.modulus == cli_modulus

    def test_cli_generator_accessor(self, cli, cli_generator):
        assert cli.generator == cli_generator

    def test_cli_key_size_accessor(self, cli):
        assert cli.key_size == 8

    def test_srv_access_shared_secret_without_key(self, srv):
        assert srv.shared_secret == 0

    def test_cli_access_shared_secret_without_key(self, cli):
        assert cli.shared_secret == 0

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
    @pytest.fixture(autouse=True, params=get_supported_curves())
    def _setup(self, request):
        curve = request.param
        self.srv = ECDHServer(curve)
        self.cli = ECDHClient(curve)

    def test_key_accessors_without_key(self):
        for cipher in (self.srv, self.cli):
            assert not cipher._has_private()
            assert not cipher._has_public()
            assert cipher.shared_secret == 0

    def test_exchange(self):
        ske = self.srv.generate()
        assert self.srv._has_public()

        self.cli.import_SKE(ske)
        assert self.cli._has_peers_public() is True

        cke = self.cli.generate()
        assert self.cli._has_public()

        self.srv.import_CKE(cke)
        assert self.srv._has_peers_public() is True

        srv_sec = self.srv.generate_secret()
        cli_sec = self.cli.generate_secret()
        assert srv_sec == cli_sec
        assert srv_sec == self.srv.shared_secret
        assert cli_sec == self.cli.shared_secret


class TestECDHNaive:
    @pytest.fixture(autouse=True, params=(Curve.CURVE25519, Curve.CURVE448))
    def _setup(self, request):
        curve = request.param
        self.alice = ECDHNaive(curve)
        self.bob = ECDHNaive(curve)

    def test_key_accessors_without_key(self):
        for peer in (self.alice, self.bob):
            assert not peer._has_private()
            assert not peer._has_public()
            assert peer.shared_secret == 0
            assert peer._private_key == 0
            assert peer._public_key == 0
            assert peer._peer_public_key == 0

    def test_exchange(self):
        alice_to_bob = self.alice.generate()
        assert self.alice._has_public()

        bob_to_alice = self.bob.generate()
        assert self.bob._has_public()

        assert self.alice._private_key != 0
        assert self.bob._private_key != 0
        assert self.alice._private_key != self.bob._private_key

        assert self.alice._public_key != 0
        assert self.bob._public_key != 0
        assert self.alice._public_key != self.bob._public_key

        self.alice.import_peer_public(bob_to_alice)
        assert self.alice._has_peers_public() is True
        assert self.alice._peer_public_key == self.bob._public_key

        self.bob.import_peer_public(alice_to_bob)
        assert self.bob._has_peers_public() is True
        assert self.bob._peer_public_key == self.alice._public_key

        alice_secret = self.alice.generate_secret()
        bob_secret = self.bob.generate_secret()
        assert alice_secret == bob_secret
        assert alice_secret == self.alice.shared_secret
        assert bob_secret == self.bob.shared_secret
