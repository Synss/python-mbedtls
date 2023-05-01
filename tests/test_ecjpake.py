# SPDX-License-Identifier: MIT

"""Unit tests for mbedtls.ecjpake."""

from __future__ import annotations

import pytest

from mbedtls import hashlib, version

if not version.has_feature("MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED"):
    pytest.skip("unsupported feature", allow_module_level=True)

from mbedtls.ecjpake import _get_md_alg  # type: ignore
from mbedtls.ecjpake import ECJPAKE, Curve, RoleType, get_supported_curves


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
        # Curve.CURVE25519,
        # Curve.CURVE448,
    ]


class TestECJPAKE:
    # pylint: disable=protected-access

    @pytest.mark.parametrize("secret", [b"123456"])
    def test_exchange_default_args(self, secret: bytes) -> None:
        srv = ECJPAKE(RoleType.SERVER.value, secret)
        cli = ECJPAKE(RoleType.CLIENT.value, secret)

        srv_ready = srv.check_ready()
        assert srv_ready

        cli_ready = cli.check_ready()
        assert cli_ready

        srv_r1 = srv.write_round_one()
        assert srv_r1 is not None

        cli_r1 = cli.write_round_one()
        assert cli_r1 is not None

        cli.read_round_one(srv_r1)
        srv.read_round_one(cli_r1)

        srv_r2 = srv.write_round_two()
        assert srv_r2 is not None

        cli_r2 = cli.write_round_two()
        assert cli_r2 is not None

        cli.read_round_two(srv_r2)
        srv.read_round_two(cli_r2)

        cli_secret = cli.derive_secret()
        srv_secret = srv.derive_secret()
        assert cli_secret == srv_secret

    @pytest.mark.parametrize(
        "digestmod",
        [_get_md_alg(name) for name in hashlib.algorithms_guaranteed],
        ids=lambda dm: dm().name,  # type: ignore[no-any-return]
    )
    def test_exchange_explicit_md_arg(self, digestmod: str) -> None:
        secret = b"123456"
        srv = ECJPAKE(RoleType.SERVER.value, secret, digestmod=digestmod)
        cli = ECJPAKE(RoleType.CLIENT.value, secret, digestmod=digestmod)

        srv_ready = srv.check_ready()
        assert srv_ready

        cli_ready = cli.check_ready()
        assert cli_ready

        srv_r1 = srv.write_round_one()
        assert srv_r1 is not None

        cli_r1 = cli.write_round_one()
        assert cli_r1 is not None

        cli.read_round_one(srv_r1)
        srv.read_round_one(cli_r1)

        srv_r2 = srv.write_round_two()
        assert srv_r2 is not None

        cli_r2 = cli.write_round_two()
        assert cli_r2 is not None

        cli.read_round_two(srv_r2)
        srv.read_round_two(cli_r2)

        cli_secret = cli.derive_secret()
        srv_secret = srv.derive_secret()
        assert cli_secret == srv_secret

    @pytest.mark.parametrize("curve", get_supported_curves())
    def test_exchange_explicit_curve_arg(self, curve: Curve) -> None:
        secret = b"123456"
        digestmod = "sha256"
        srv = ECJPAKE(RoleType.SERVER.value, secret, digestmod, curve)
        cli = ECJPAKE(RoleType.CLIENT.value, secret, digestmod, curve)

        srv_ready = srv.check_ready()
        assert srv_ready

        cli_ready = cli.check_ready()
        assert cli_ready

        srv_r1 = srv.write_round_one()
        assert srv_r1 is not None

        cli_r1 = cli.write_round_one()
        assert cli_r1 is not None

        cli.read_round_one(srv_r1)
        srv.read_round_one(cli_r1)

        srv_r2 = srv.write_round_two()
        assert srv_r2 is not None

        cli_r2 = cli.write_round_two()
        assert cli_r2 is not None

        cli.read_round_two(srv_r2)
        srv.read_round_two(cli_r2)

        cli_secret = cli.derive_secret()
        srv_secret = srv.derive_secret()
        assert cli_secret == srv_secret

    def test_exchange_fail_nonmatching_secrets(self) -> None:
        srv = ECJPAKE(RoleType.SERVER.value, b"123456")
        cli = ECJPAKE(RoleType.CLIENT.value, b"abcdef")

        srv_ready = srv.check_ready()
        assert srv_ready

        cli_ready = cli.check_ready()
        assert cli_ready

        srv_r1 = srv.write_round_one()
        assert srv_r1 is not None

        cli_r1 = cli.write_round_one()
        assert cli_r1 is not None

        cli.read_round_one(srv_r1)
        srv.read_round_one(cli_r1)

        srv_r2 = srv.write_round_two()
        assert srv_r2 is not None

        cli_r2 = cli.write_round_two()
        assert cli_r2 is not None

        cli.read_round_two(srv_r2)
        srv.read_round_two(cli_r2)

        cli_secret = cli.derive_secret()
        srv_secret = srv.derive_secret()
        assert cli_secret != srv_secret

    def test_fail_server_init(self) -> None:
        with pytest.raises(TypeError):
            srv = ECJPAKE(RoleType.SERVER.value, None)  # type: ignore[arg-type]
            assert srv is None

    def test_fail_client_init(self) -> None:
        with pytest.raises(TypeError):
            srv = ECJPAKE(RoleType.CLIENT.value, None)  # type: ignore[arg-type]
            assert srv is None
