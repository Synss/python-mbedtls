"""Unit tests for mbedtls.md."""

# Disable checks for violations that are acceptable in tests.
# pylint: disable=missing-docstring
# pylint: disable=attribute-defined-outside-init
# pylint: disable=invalid-name
from functools import partial
import hashlib
import hmac
import inspect

import pytest

# pylint: disable=import-error
import mbedtls
import mbedtls.hash as md_hash
import mbedtls.hmac as md_hmac
from mbedtls._md import MD_NAME

# pylint: enable=import-error


def make_chunks(buffer, size):
    for i in range(0, len(buffer), size):
        yield buffer[i : i + size]


def test_make_chunks(randbytes):
    buffer = randbytes(1024)
    assert b"".join(buf for buf in make_chunks(buffer, 100)) == buffer


def test_md_list():
    assert len(MD_NAME) == 10


def test_algorithms():
    assert set(md_hash.algorithms_guaranteed).issubset(
        md_hash.algorithms_available
    )


class _TestMDBase:
    @pytest.fixture
    def algorithm(self):
        raise NotImplementedError

    @pytest.fixture
    def digest_size(self):
        raise NotImplementedError

    @pytest.fixture
    def block_size(self):
        raise NotImplementedError

    def test_digest_size_accessor(self, algorithm, digest_size):
        assert algorithm.digest_size == digest_size

    def test_digest_size(self, algorithm, digest_size):
        assert len(algorithm.digest()) == digest_size

    def test_block_size_accessor(self, algorithm, block_size):
        assert algorithm.block_size == block_size


class _TestHash(_TestMDBase):
    @pytest.fixture
    def buffer(self, randbytes):
        return randbytes(512)

    def test_new(self, algorithm, buffer):
        copy = md_hash.new(algorithm.name, buffer)
        algorithm.update(buffer)
        assert algorithm.digest() == copy.digest()
        assert algorithm.hexdigest() == copy.hexdigest()

    def test_copy_and_update(self, algorithm, buffer):
        copy = algorithm.copy()
        algorithm.update(buffer)
        copy.update(buffer)
        assert algorithm.digest() == copy.digest()
        assert algorithm.hexdigest() == copy.hexdigest()

    def test_copy_and_update_nothing(self, algorithm, buffer):
        copy = algorithm.copy()
        algorithm.update(b"")
        assert algorithm.digest() == copy.digest()
        assert algorithm.hexdigest() == copy.hexdigest()


@pytest.mark.skipif(
    not mbedtls.has_feature("md2"), reason="requires MD2 support in libmbedtls"
)
class TestHashMD2(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.md2()


@pytest.mark.skipif(
    not mbedtls.has_feature("md4"), reason="requires MD4 support in libmbedtls"
)
class TestHashMD4(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.md4()


@pytest.mark.skipif(
    not mbedtls.has_feature("md5"), reason="requires MD5 support in libmbedtls"
)
class TestHashMD5(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.md5()

    @pytest.fixture
    def type_(self):
        return 3

    @pytest.fixture
    def digest_size(self):
        return 16

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha1"),
    reason="requires SHA1 support in libmbedtls",
)
class TestHashSHA1(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.sha1()

    @pytest.fixture
    def digest_size(self):
        return 20

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha256"),
    reason="requires SHA256 support in libmbedtls",
)
class TestHashSHA224(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.sha224()

    @pytest.fixture
    def digest_size(self):
        return 28

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha256"),
    reason="requires SHA256 support in libmbedtls",
)
class TestHashSHA256(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.sha256()

    @pytest.fixture
    def digest_size(self):
        return 32

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha512"),
    reason="requires SHA384 support in libmbedtls",
)
class TestHashSHA384(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.sha384()

    @pytest.fixture
    def digest_size(self):
        return 48

    @pytest.fixture
    def block_size(self):
        return 128


@pytest.mark.skipif(
    not mbedtls.has_feature("sha512"),
    reason="requires SHA512 support in libmbedtls",
)
class TestHashSHA512(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.sha512()

    @pytest.fixture
    def digest_size(self):
        return 64

    @pytest.fixture
    def block_size(self):
        return 128


@pytest.mark.skipif(
    not mbedtls.has_feature("ripemd160"),
    reason="requires RIPEMD160 support in libmbedtls",
)
class TestHashRIPEMD160(_TestHash):
    @pytest.fixture
    def algorithm(self):
        return md_hash.ripemd160()

    @pytest.fixture
    def digest_size(self):
        return 20

    @pytest.fixture
    def block_size(self):
        return 64


class _TestHmac(_TestMDBase):
    @pytest.fixture(params=[0, 16])
    def key(self, request, randbytes):
        return randbytes(request.param)

    @pytest.fixture
    def buffer(self, randbytes):
        return randbytes(512)

    def test_new(self, algorithm, key, buffer):
        copy = md_hmac.new(key, buffer, algorithm.name)
        algorithm.update(buffer)
        assert algorithm.digest() == copy.digest()
        assert algorithm.hexdigest() == copy.hexdigest()


@pytest.mark.skipif(
    not mbedtls.has_feature("md2"), reason="requires MD2 support in libmbedtls"
)
class TestHmacMD2(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.md2(key)


@pytest.mark.skipif(
    not mbedtls.has_feature("md4"), reason="requires MD4 support in libmbedtls"
)
class TestHmacMD4(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.md4(key)


@pytest.mark.skipif(
    not mbedtls.has_feature("md5"), reason="requires MD5 support in libmbedtls"
)
class TestHmacMD5(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.md5(key)

    @pytest.fixture
    def type_(self):
        return 3

    @pytest.fixture
    def digest_size(self):
        return 16

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha1"),
    reason="requires SHA1 support in libmbedtls",
)
class TestHmacSHA1(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.sha1(key)

    @pytest.fixture
    def digest_size(self):
        return 20

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha256"),
    reason="requires SHA256 support in libmbedtls",
)
class TestHmacSHA224(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.sha224(key)

    @pytest.fixture
    def digest_size(self):
        return 28

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha256"),
    reason="requires SHA256 support in libmbedtls",
)
class TestHmacSHA256(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.sha256(key)

    @pytest.fixture
    def digest_size(self):
        return 32

    @pytest.fixture
    def block_size(self):
        return 64


@pytest.mark.skipif(
    not mbedtls.has_feature("sha512"),
    reason="requires SHA512 support in libmbedtls",
)
class TestHmacSHA384(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.sha384(key)

    @pytest.fixture
    def digest_size(self):
        return 48

    @pytest.fixture
    def block_size(self):
        return 128


@pytest.mark.skipif(
    not mbedtls.has_feature("sha512"),
    reason="requires SHA512 support in libmbedtls",
)
class TestHmacSHA512(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.sha512(key)

    @pytest.fixture
    def digest_size(self):
        return 64

    @pytest.fixture
    def block_size(self):
        return 128


@pytest.mark.skipif(
    not mbedtls.has_feature("ripemd160"),
    reason="requires RIPEMD160 support in libmbedtls",
)
class TestHmacRIPEMD160(_TestHmac):
    @pytest.fixture
    def algorithm(self, key):
        return md_hmac.ripemd160(key)

    @pytest.fixture
    def digest_size(self):
        return 20

    @pytest.fixture
    def block_size(self):
        return 64
