# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

from typing import Optional

from .hmac import Algorithm

def hkdf(
    key: bytes,
    length: int,
    info: bytes,
    salt: Optional[bytes] = None,
    digestmod: Optional[Algorithm] = None,
) -> bytes: ...
def extract(
    key: bytes,
    salt: Optional[bytes] = None,
    digestmod: Optional[Algorithm] = None,
) -> bytes: ...
def expand(
    prk: bytes,
    length: int,
    info: bytes,
    digestmod: Optional[Algorithm] = None,
) -> bytes: ...
