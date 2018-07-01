"""Unit test mbedtls.exceptions."""

import pytest

from mbedtls.exceptions import check_error, MbedTLSError


@pytest.mark.parametrize(
    "err, msg",
    ((0x003C, "ENTROPY"), (0x1080, "PEM"), (0x2200, "X509")))
def test_mbedtls_error(err, msg):
    with pytest.raises(MbedTLSError, match=r"%s - .+" % msg) as exc:
        check_error(-err)


def test_other_error():
    with pytest.raises(MbedTLSError, match="error message") as exc:
        raise MbedTLSError(msg="error message")
