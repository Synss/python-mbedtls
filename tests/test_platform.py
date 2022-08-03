# SPDX-License-Identifier: MIT

from __future__ import annotations

import mbedtls._platform as _plt


def test_zeroize_bytes() -> None:
    binary = bytearray(b"0123456789abcdef")
    length = len(binary)

    _plt.zeroize(binary)

    assert len(binary) == length
    assert binary == b"\0" * length
