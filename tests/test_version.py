# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from mbedtls import version


def test_version_info() -> None:
    assert len(version.version_info) == 3
    assert version.version_info >= (2, 7, 9)


def test_version() -> None:
    major, minor, micro = version.version_info
    assert (
        version.version.lower() == f"Mbed TLS {major}.{minor}.{micro}".lower()
    )


@pytest.mark.parametrize("feature", ["i do not exist"])
def test_feature_false(feature: str) -> None:
    assert version.has_feature(feature) is False


@pytest.mark.parametrize(
    "feature",
    [
        "md5",
        "md5_c",
        "mbedtls_md5",
        "mbedtls_md5_c",
        "MD5",
        "MD5_C",
        "MBEDTLS_MD5",
        "MBEDTLS_MD5_C",
    ],
)
def test_feature_true(feature: str) -> None:
    assert version.has_feature(feature) is True
