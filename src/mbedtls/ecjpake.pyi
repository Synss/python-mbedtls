# SPDX-License-Identifier: MIT

from __future__ import annotations

import enum
import os
import sys
from typing import (
    NoReturn,
    Optional,
    Sequence,
    Union,
)

if sys.version_info < (3, 9):
    _PathLike = os.PathLike
else:
    _PathLike = os.PathLike[str]

_Path = Union[_PathLike, str]

class RoleType(int, enum.Enum):
    SERVER: int
    CLIENT: int

class Curve(bytes, enum.Enum):
    SECP192R1: bytes
    SECP224R1: bytes
    SECP256R1: bytes
    SECP384R1: bytes
    SECP521R1: bytes
    BRAINPOOLP256R1: bytes
    BRAINPOOLP384R1: bytes
    BRAINPOOLP512R1: bytes
    SECP192K1: bytes
    SECP224K1: bytes
    SECP256K1: bytes
    CURVE25519: bytes
    CURVE448: bytes

def get_supported_hashes() -> Sequence[bytes]: ...
def get_supported_curves() -> Sequence[Curve]: ...

class ECJPAKE:
    def __init__(
        self,
        role: int,
        secret: bytes,
        digestmod: Optional[str] = ...,
        curve: Optional[Curve] = ...) -> None: ...
    def __getstate__(self) -> NoReturn: ...
    def check_ready(self) -> bool: ...
    def write_round_one(self) -> bytes: ...
    def read_round_one(self, message: bytes) -> NoReturn: ...
    def write_round_two(self) -> bytes: ...
    def read_round_two(self, message: bytes) -> NoReturn: ...
    def derive_secret(self) -> bytes: ...
