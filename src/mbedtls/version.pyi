# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

import sys
from typing import NamedTuple

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final

class mbedtls_version(NamedTuple):
    major: int
    minor: int
    micro: int

def has_feature(feature: str) -> bool: ...

version_info: Final[mbedtls_version]
version: Final[str]
