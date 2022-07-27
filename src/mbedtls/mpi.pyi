# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

import numbers
import sys
from typing import Any, NoReturn, Optional, Tuple, Union, overload

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal

_Integral = Union[numbers.Integral, int]

class MPI(numbers.Integral):
    def __init__(self, __value: _Integral = 0) -> None: ...
    def __reduce__(self) -> Tuple[Any, ...]: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def bit_length(self) -> int: ...
    @classmethod
    def from_int(cls, __value: int) -> MPI: ...
    @classmethod
    def from_bytes(
        cls, __data: bytes, byteorder: Literal["big", "little"] = "big"
    ) -> MPI: ...
    def to_bytes(
        self, length: int, byteorder: Literal["big", "little"]
    ) -> bytes: ...
    @classmethod
    def prime(cls, size: int) -> MPI: ...
    def __hash__(self) -> int: ...
    def __bool__(self) -> bool: ...
    def __add__(self, __other: object) -> MPI: ...
    def __radd__(self, __other: object) -> MPI: ...
    def __neg__(self) -> NoReturn: ...
    def __pos__(self) -> MPI: ...
    def __sub__(self, __other: object) -> MPI: ...
    def __mul__(self, __other: object) -> MPI: ...
    def __rmul__(self, __other: object) -> MPI: ...
    def __truediv__(self, __other: object) -> MPI: ...
    def __rtruediv__(self, __other: object) -> MPI: ...
    def __pow__(
        self, __exponent: _Integral, __modulus: Optional[_Integral] = ...
    ) -> MPI: ...
    def __rpow__(self, __other: Any) -> Any: ...
    def __abs__(self) -> MPI: ...
    def __eq__(self, __other: object) -> bool: ...
    def __float__(self) -> float: ...
    # mypy wants int but that should be Integral according to
    # the documentation to trunc, floor, and ceil.
    def __trunc__(self) -> int: ...
    def __floor__(self) -> int: ...
    def __ceil__(self) -> int: ...
    @overload
    def __round__(self, ndigits: None = ...) -> int: ...
    @overload
    def __round__(self, ndigits: int) -> _Integral: ...
    def __divmod__(self, __other: _Integral) -> Tuple[MPI, MPI]: ...
    def __floordiv__(self, __other: object) -> int: ...
    def __rfloordiv__(self, __other: object) -> int: ...
    def __mod__(self, __other: _Integral) -> MPI: ...
    def __rmod__(self, __other: _Integral) -> MPI: ...
    def __lt__(self, __other: _Integral) -> bool: ...
    def __le__(self, __other: _Integral) -> bool: ...
    def __gt__(self, __other: _Integral) -> bool: ...
    def __ge__(self, __other: _Integral) -> bool: ...
    def __complex__(self) -> complex: ...
    def __real__(self) -> MPI: ...
    def imag(self) -> Literal[0]: ...
    def conjugate(self) -> MPI: ...
    def __int__(self) -> int: ...
    def __index__(self) -> int: ...
    def __lshift__(self, __other: _Integral) -> MPI: ...
    def __rlshift__(self, __other: _Integral) -> MPI: ...
    def __rshift__(self, __other: _Integral) -> MPI: ...
    def __rrshift__(self, __other: _Integral) -> MPI: ...
    def __and__(self, __other: _Integral) -> MPI: ...
    def __rand__(self, __other: _Integral) -> MPI: ...
    def __xor__(self, __other: _Integral) -> MPI: ...
    def __rxor__(self, __other: _Integral) -> MPI: ...
    def __or__(self, __other: _Integral) -> MPI: ...
    def __ror__(self, __other: _Integral) -> MPI: ...
    def __invert__(self) -> NoReturn: ...
    @property
    def numerator(self) -> int: ...
    @property
    def denominator(self) -> Literal[1]: ...
