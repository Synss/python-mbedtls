"""Unit test mbedtls.exceptions."""

import pytest  # type: ignore

from mbedtls.exceptions import TLSError, check_error  # type: ignore


@pytest.mark.parametrize(
    "err, msg", ((0x003C, "ENTROPY"), (0x1080, "PEM"), (0x2200, "X509"))
)
def test_mbedtls_error(err, msg):
    with pytest.raises(TLSError, match=r"%s - .+" % msg) as exc:
        check_error(-err)


def test_other_error():
    with pytest.raises(TLSError, match="error message") as exc:
        raise TLSError(msg="error message")
