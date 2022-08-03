# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any, Callable, cast

import pytest

import mbedtls
import mbedtls.hkdf as _hkdf
import mbedtls.hmac as _hmac
from mbedtls.hmac import Algorithm


@pytest.mark.skipif(
    not mbedtls.has_feature("HKDF"),
    reason="requires HKDF support in libmbedtls",
)
class TestHKDF:
    @pytest.fixture(
        params=[
            _hmac.md2,
            _hmac.md4,
            _hmac.md5,
            _hmac.sha1,
            _hmac.sha224,
            _hmac.sha256,
            _hmac.sha384,
            _hmac.sha512,
            _hmac.ripemd160,
        ]
    )
    def hmac(self, request: Any) -> Algorithm:
        feature = request.param.__name__
        if not mbedtls.has_feature(
            {"sha224": "sha256", "sha384": "sha512"}.get(feature, feature)
        ):
            return pytest.skip("requires %s support in mbedtls" % feature)
        return cast(Algorithm, request.param)

    @pytest.mark.parametrize("key_length", [0, 128])
    def test_hkdf(
        self, key_length: int, randbytes: Callable[[int], bytes]
    ) -> None:
        key = randbytes(key_length)
        okm = _hkdf.hkdf(key, 32, b"")
        assert len(okm) == 32

    @pytest.mark.parametrize("key_length", [0, 128])
    @pytest.mark.parametrize("info_length", [16, 128, 500, 1000])
    @pytest.mark.parametrize("output_length", [16, 200, 500])
    def test_hkdf_with_options(
        self,
        key_length: int,
        info_length: int,
        output_length: int,
        hmac: Algorithm,
        randbytes: Callable[[int], bytes],
    ) -> None:
        key = randbytes(key_length)
        info = randbytes(info_length)
        salt = randbytes(hmac(key).digest_size)

        okm = _hkdf.hkdf(key, output_length, info, salt, hmac)
        assert len(okm) == output_length

    @pytest.mark.parametrize("key_length", [0, 128])
    def test_extract_and_expand(
        self, key_length: int, randbytes: Callable[[int], bytes]
    ) -> None:
        key = randbytes(key_length)
        prk = _hkdf.extract(key)
        assert len(prk) == _hmac.sha256(b"").digest_size

        okm = _hkdf.expand(prk, 32, b"")
        assert len(okm) == 32

    @pytest.mark.parametrize("key_length", [0, 128])
    @pytest.mark.parametrize("info_length", [16, 128, 500, 1000])
    @pytest.mark.parametrize("output_length", [16, 200, 500])
    def test_extract_and_expand_with_options(
        self,
        key_length: int,
        info_length: int,
        output_length: int,
        hmac: Algorithm,
        randbytes: Callable[[int], bytes],
    ) -> None:
        key = randbytes(key_length)
        info = randbytes(info_length)
        salt = randbytes(hmac(key).digest_size)

        prk = _hkdf.extract(key, salt, hmac)
        assert len(prk) == hmac(b"").digest_size

        okm = _hkdf.expand(prk, output_length, info, hmac)
        assert len(okm) == output_length


def to_bytes(number: int, size: int) -> bytes:
    return number.to_bytes(size, byteorder="big")


class TestHKDF_RFC5869_TestVectors:
    def test_case_1(self) -> None:
        algorithm = _hmac.sha256
        ikm = to_bytes(0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B, 22)
        salt = to_bytes(0x000102030405060708090A0B0C, 13)
        info = to_bytes(0xF0F1F2F3F4F5F6F7F8F9, 10)
        length = 42
        prk = to_bytes(
            int(
                "0x077709362c2e32df0ddc3f0dc47bba63"
                "90b6c73bb50f9c3122ec844ad7c2b3e5",
                0,
            ),
            32,
        )
        okm = to_bytes(
            int(
                "0x3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865",
                0,
            ),
            42,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_2(self) -> None:
        algorithm = _hmac.sha256
        ikm = to_bytes(
            int(
                "0x000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f",
                0,
            ),
            80,
        )
        salt = to_bytes(
            int(
                "0x606162636465666768696a6b6c6d6e6f"
                "707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                0,
            ),
            80,
        )
        info = to_bytes(
            int(
                "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                0,
            ),
            80,
        )
        length = 82
        prk = to_bytes(
            int(
                "0x06a6b88c5853361a06104c9ceb35b45c"
                "ef760014904671014a193f40c15fc244",
                0,
            ),
            32,
        )
        okm = to_bytes(
            int(
                "0xb11e398dc80327a1c8e7f78c596a4934"
                "4f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f"
                "1d87",
                0,
            ),
            82,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_3(self) -> None:
        algorithm = _hmac.sha256
        ikm = to_bytes(0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B, 22)
        salt = b""
        info = b""
        length = 42
        prk = to_bytes(
            int(
                "0x19ef24a32c717b167f33a91d6f648bdf"
                "96596776afdb6377ac434c1c293ccb04",
                0,
            ),
            32,
        )
        okm = to_bytes(
            int(
                "0x8da4e775a563c18f715f802a063c5a31"
                "b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8",
                0,
            ),
            42,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_4(self) -> None:
        algorithm = _hmac.sha1
        ikm = to_bytes(0x0B0B0B0B0B0B0B0B0B0B0B, 11)
        salt = to_bytes(0x000102030405060708090A0B0C, 13)
        info = to_bytes(0xF0F1F2F3F4F5F6F7F8F9, 10)
        length = 42
        prk = to_bytes(0x9B6C18C432A7BF8F0E71C8EB88F4B30BAA2BA243, 20)
        okm = to_bytes(
            int(
                "0x085a01ea1b10f36933068b56efa5ad81"
                "a4f14b822f5b091568a9cdd4f155fda2"
                "c22e422478d305f3f896",
                0,
            ),
            42,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_5(self) -> None:
        algorithm = _hmac.sha1
        ikm = to_bytes(
            int(
                "0x000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f",
                0,
            ),
            80,
        )
        salt = to_bytes(
            int(
                "0x606162636465666768696a6b6c6d6e6f"
                "707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                0,
            ),
            80,
        )
        info = to_bytes(
            int(
                "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                0,
            ),
            80,
        )
        length = 82
        prk = to_bytes(0x8ADAE09A2A307059478D309B26C4115A224CFAF6, 20)
        okm = to_bytes(
            int(
                "0x0bd770a74d1160f7c9f12cd5912a06eb"
                "ff6adcae899d92191fe4305673ba2ffe"
                "8fa3f1a4e5ad79f3f334b3b202b2173c"
                "486ea37ce3d397ed034c7f9dfeb15c5e"
                "927336d0441f4c4300e2cff0d0900b52"
                "d3b4",
                0,
            ),
            82,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_6(self) -> None:
        algorithm = _hmac.sha1
        ikm = to_bytes(0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B, 22)
        salt = b""
        info = b""
        length = 42
        prk = to_bytes(0xDA8C8A73C7FA77288EC6F5E7C297786AA0D32D01, 20)
        okm = to_bytes(
            int(
                "0x0ac1af7002b3d761d1e55298da9d0506"
                "b9ae52057220a306e07b6b87e8df21d0"
                "ea00033de03984d34918",
                0,
            ),
            42,
        )

        assert _hkdf.extract(ikm, salt, algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, salt, algorithm) == okm

    def test_case_7(self) -> None:
        algorithm = _hmac.sha1
        ikm = to_bytes(0x0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C, 22)
        info = b""
        length = 42
        prk = to_bytes(0x2ADCCADA18779E7C2077AD2EB19D3F3E731385DD, 20)
        okm = to_bytes(
            int(
                "0x2c91117204d745f3500d636a62f64f0a"
                "b3bae548aa53d423b0d1f27ebba6f5e5"
                "673a081d70cce7acfc48",
                0,
            ),
            42,
        )

        assert _hkdf.extract(ikm, digestmod=algorithm) == prk
        assert _hkdf.expand(prk, length, info, algorithm) == okm
        assert _hkdf.hkdf(ikm, length, info, digestmod=algorithm) == okm
