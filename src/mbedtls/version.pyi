# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

from typing import Final, NamedTuple

class mbedtls_version(NamedTuple):
    major: int
    minor: int
    micro: int

def has_feature(feature: str) -> bool: ...

version_info: Final[mbedtls_version]
version: Final[str]
