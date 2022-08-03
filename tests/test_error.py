# SPDX-License-Identifier: MIT

"""Unit test mbedtls.exceptions."""

from __future__ import annotations

from typing import Tuple

import pytest

from mbedtls.exceptions import check_error  # type: ignore
from mbedtls.exceptions import TLSError


@pytest.mark.parametrize(
    "err_msg", [(0x003C, "ENTROPY"), (0x1080, "PEM"), (0x2200, "X509")]
)
def test_mbedtls_error(err_msg: Tuple[int, str]) -> None:
    err, msg = err_msg
    with pytest.raises(TLSError, match=r"%s - .+" % msg):
        check_error(-err)


def test_other_error() -> None:
    with pytest.raises(TLSError, match="error message"):
        raise TLSError(msg="error message")
