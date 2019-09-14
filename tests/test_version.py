import pytest

from mbedtls import version


def test_version_info():
    assert len(version.version_info) == 3
    assert version.version_info >= (2, 7, 9)


def test_version():
    assert version.version == "mbed TLS %i.%i.%i" % version.version_info


@pytest.mark.parametrize(
    "feature, present",
    (
        ("havege", False),
        ("MBEDTLS_SSL_RENEGOTIATION", True),
        ("ssl_renegotiation", True),
        ("md5", True),
        ("MD5_C", True),
    ),
)
def test_feature(feature, present):
    assert version.has_feature(feature) is present
