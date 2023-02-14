# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

import enum
import numbers
import os
import sys
from typing import (
    Callable,
    Final,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Type,
    TypeVar,
    Union,
    overload,
)

if sys.version_info < (3, 9):
    _Path = Union[os.PathLike, str]  # type: ignore [type-arg]
else:
    _Path = Union[os.PathLike[str], str]

CIPHER_NAME: Final[Sequence[bytes]] = ...
_DER = bytes
_PEM = str
_MPI = Union[numbers.Integral, int]

class CipherType(enum.Enum):
    NONE: int
    RSA: int
    ECKEY: int
    ECKEY_DH: int
    ECDSA: int
    RSA_ALT: int
    RSASSA_PSS: int

class KeyPair(NamedTuple):
    private: Union[_DER, _PEM]
    public: Union[_DER, _PEM]

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

def check_pair(pub: CipherBase, priv: CipherBase) -> bool: ...
def get_supported_ciphers() -> Sequence[bytes]: ...
def get_supported_curves() -> Sequence[Curve]: ...

# `Self` (PEP 673) should work as well but did not with typing_extensions 4.2.0
_TCipherBase = TypeVar("_TCipherBase", bound=CipherBase)

class CipherBase:
    def __init__(
        self,
        name: bytes,
        key: Optional[bytes] = ...,
        password: Optional[bytes] = ...,
    ) -> None: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __str__(self) -> _PEM: ...
    def __bytes__(self) -> _DER: ...
    def to_bytes(self) -> _DER: ...
    @classmethod
    def from_buffer(
        cls: Type[_TCipherBase],
        buffer: bytes,
        password: Optional[
            Union[Callable[[], Union[bytes, bytearray]], bytes, bytearray]
        ] = None,
    ) -> _TCipherBase: ...
    @classmethod
    def from_file(
        cls: Type[_TCipherBase],
        path: _Path,
        password: Optional[
            Union[Callable[[], Union[bytes, bytearray]], bytes, bytearray]
        ] = None,
    ) -> _TCipherBase: ...
    @classmethod
    def from_DER(cls: Type[_TCipherBase], key: bytes) -> _TCipherBase: ...
    @classmethod
    def from_PEM(cls: Type[_TCipherBase], key: str) -> _TCipherBase: ...
    @property
    def name(self) -> bytes: ...
    @property
    def key_size(self) -> int: ...
    def _has_private(self) -> bool: ...
    def _has_public(self) -> bool: ...
    def sign(
        self, message: bytes, digestmod: Optional[str] = ...
    ) -> bytes: ...
    def verify(
        self, message: bytes, signature: bytes, digestmod: str
    ) -> bool: ...
    def encrypt(self, message: bytes) -> bytes: ...
    def decrypt(self, message: bytes) -> bytes: ...

class RSA(CipherBase):
    def __init__(
        self, key: Optional[bytes] = ..., password: Optional[bytes] = ...
    ) -> None: ...
    def generate(self, key_size: int = ..., exponent: int = ...) -> _DER: ...
    @overload
    def export_key(self, format: Literal["DER"]) -> _DER: ...
    @overload
    def export_key(self, format: Literal["PEM"]) -> _PEM: ...
    @overload
    def export_key(self) -> Union[_DER, _PEM]: ...
    @overload
    def export_public_key(self, format: Literal["DER"]) -> _DER: ...
    @overload
    def export_public_key(self, format: Literal["PEM"]) -> _PEM: ...
    @overload
    def export_public_key(self) -> Union[_DER, _PEM]: ...

class ECC(CipherBase):
    def __init__(
        self,
        curve: Optional[Curve] = ...,
        key: Optional[bytes] = ...,
        password: Optional[bytes] = ...,
    ) -> None: ...
    @property
    def curve(self) -> Curve: ...
    def generate(self) -> bytes: ...
    @overload
    def export_key(self, format: Literal["DER"]) -> _DER: ...
    @overload
    def export_key(self, format: Literal["PEM"]) -> _PEM: ...
    @overload
    def export_key(self) -> Union[_DER, _PEM]: ...
    @overload
    def export_public_key(self, format: Literal["DER"]) -> _DER: ...
    @overload
    def export_public_key(self, format: Literal["PEM"]) -> _PEM: ...
    @overload
    def export_public_key(self) -> Union[_DER, _PEM]: ...
