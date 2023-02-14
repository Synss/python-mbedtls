# SPDX-License-Identifier: MIT

"""Unit tests for mbedtls.pk."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path
from typing import Any, Callable, List, Union, cast

import pytest

from mbedtls import hashlib
from mbedtls.pk import _get_md_alg  # type: ignore
from mbedtls.pk import (
    ECC,
    RSA,
    Curve,
    check_pair,
    get_supported_ciphers,
    get_supported_curves,
)

if sys.version_info < (3, 11):
    from typing_extensions import assert_never
else:
    from typing import assert_never


_CipherType = Union[RSA, ECC]


def test_supported_curves() -> None:
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


def test_get_supported_ciphers() -> None:
    assert list(get_supported_ciphers()) == [
        b"NONE",
        b"RSA",
        b"EC",
        b"EC_DH",
        b"ECDSA",
    ]


def test_rsa_encryp_decrypt(randbytes: Callable[[int], bytes]) -> None:
    rsa = RSA()
    rsa.generate(1024)
    msg = randbytes(rsa.key_size - 11)
    assert rsa.decrypt(rsa.encrypt(msg)) == msg


def do_generate(cipher: _CipherType) -> bytes:
    if isinstance(cipher, RSA):
        return cipher.generate(1024)
    if isinstance(cipher, ECC):
        return cipher.generate()
    assert_never(cipher)


class TestCipher:
    @pytest.fixture(
        params=[cast(object, RSA)]
        + cast(
            List[object],
            [
                curve
                for curve in get_supported_curves()
                if curve not in (Curve.CURVE25519, Curve.CURVE448)
            ],
        )
    )
    def cipher(self, request: Any) -> _CipherType:
        if request.param is RSA:
            return cast(RSA, request.param())
        return ECC(request.param)

    def test_pickle(self, cipher: _CipherType) -> None:
        assert cipher == pickle.loads(pickle.dumps(cipher))

    def test_hash(self, cipher: _CipherType) -> None:
        assert isinstance(hash(cipher), int)

    def test_export_private_key(
        self, cipher: _CipherType, tmp_path: Path
    ) -> None:
        cipher_tag = {RSA: "RSA", ECC: "EC"}[type(cipher)]

        assert cipher.export_key("DER") == b""
        assert cipher.export_key("PEM") == ""
        assert cipher.key_size == 0

        der = do_generate(cipher)
        assert der
        assert cipher.key_size > 0

        assert der == cipher.export_key()
        assert der == cipher.export_key("DER")
        assert der == bytes(cipher)
        assert der == cipher
        assert cipher == type(cipher).from_DER(der)

        pem = cipher.export_key("PEM")
        assert pem.startswith(f"-----BEGIN {cipher_tag} PRIVATE KEY-----\n")
        assert pem.endswith(f"-----END {cipher_tag} PRIVATE KEY-----\n")
        assert pem == str(cipher)
        assert cipher == type(cipher).from_PEM(pem)

    @pytest.mark.parametrize(
        "copy",
        [
            lambda cipher: type(cipher).from_DER(cipher.export_key("DER")),
            lambda cipher: type(cipher).from_PEM(cipher.export_key("PEM")),
        ],
    )
    def test_import_private_key(
        self, cipher: _CipherType, copy: Callable[[_CipherType], _CipherType]
    ) -> None:
        assert not cipher.export_key()
        assert not cipher.export_public_key()

        key = do_generate(cipher)
        assert key

        other = copy(cipher)
        other = type(cipher).from_buffer(key)
        assert bytes(other) == key

        assert other == cipher
        assert other.export_key() == cipher.export_key() == key
        assert other.export_public_key() == cipher.export_public_key()
        assert check_pair(cipher, other) is True  # Test private half.
        assert check_pair(other, cipher) is True  # Test public half.
        assert check_pair(other, other) is True

    def test_import_from_file(
        self, cipher: _CipherType, tmp_path: Path
    ) -> None:
        do_generate(cipher)

        prv_der_file = tmp_path / "crt.prv.der"
        prv_der_file.write_bytes(cipher.export_key("DER"))
        assert cipher == type(cipher).from_file(prv_der_file)
        prv_der_file.unlink()

        pub_der_file = tmp_path / "crt.pub.der"
        pub_der = cipher.export_public_key("DER")
        pub_der_file.write_bytes(pub_der)
        assert pub_der == type(cipher).from_file(pub_der_file)
        pub_der_file.unlink()

        prv_pem_file = tmp_path / "crt.prv.pem"
        prv_pem_file.write_text(cipher.export_key("PEM"))
        assert cipher == type(cipher).from_file(prv_pem_file)
        prv_pem_file.unlink()

        pub_pem_file = tmp_path / "crt.pub.pem"
        pub_pem = cipher.export_public_key("PEM")
        pub_pem_file.write_text(pub_pem)
        assert pub_pem == type(cipher).from_file(pub_pem_file)
        pub_pem_file.unlink()

    def test_export_public_key(self, cipher: _CipherType) -> None:
        assert cipher.export_public_key("DER") == b""
        assert cipher.export_public_key("PEM") == ""

        do_generate(cipher)
        der = cipher.export_public_key("DER")
        assert der
        assert der == type(cipher).from_DER(der).export_public_key("DER")

        pem = cipher.export_public_key("PEM")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
        assert pem.endswith("-----END PUBLIC KEY-----\n")
        assert pem == type(cipher).from_PEM(pem).export_public_key("PEM")

    def test_import_public_key(self, cipher: _CipherType) -> None:
        assert not cipher.export_key()
        assert not cipher.export_public_key()

        do_generate(cipher)

        pub = cipher.export_public_key("DER")
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
    def test_sign_verify(
        self,
        cipher: _CipherType,
        digestmod: str,
        randbytes: Callable[[int], bytes],
    ) -> None:
        msg = randbytes(4096)
        assert cipher.sign(msg, digestmod) is None

        do_generate(cipher)

        sig = cipher.sign(msg, digestmod)
        assert sig is not None
        assert cipher.verify(msg, sig, digestmod) is True
        assert cipher.verify(msg + b"\0", sig, digestmod) is False


class TestECCExportKey:
    @pytest.fixture(params=get_supported_curves())
    def curve(self, request: Any) -> Curve:
        assert isinstance(request.param, Curve)
        return request.param

    def test_export_private_key(self, curve: Curve) -> None:
        ecc = ECC(curve)
        ecc.generate()

        if curve in (Curve.CURVE25519, Curve.CURVE448):
            with pytest.raises(ValueError):
                ecc.export_key("DER")
        else:
            der = ecc.export_key("DER")
            assert der
            assert ECC(curve).from_DER(der) == der

        if curve in (Curve.CURVE25519, Curve.CURVE448):
            with pytest.raises(ValueError):
                ecc.export_key("PEM")
        else:
            pem = ecc.export_key("PEM")
            assert pem
            assert pem.startswith("-----BEGIN EC PRIVATE KEY-----\n")
            assert pem.endswith("-----END EC PRIVATE KEY-----\n")

    def test_export_public(self, curve: Curve) -> None:
        ecc = ECC(curve)
        ecc.generate()

        if curve in (Curve.CURVE25519, Curve.CURVE448):
            with pytest.raises(ValueError):
                ecc.export_public_key("DER")
        else:
            der = ecc.export_public_key("DER")
            assert der

        if curve in (Curve.CURVE25519, Curve.CURVE448):
            with pytest.raises(ValueError):
                ecc.export_public_key("PEM")
        else:
            pem = ecc.export_public_key("PEM")
            assert pem
            assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
            assert pem.endswith("-----END PUBLIC KEY-----\n")
