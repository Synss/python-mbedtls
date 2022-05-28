# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from typing import Optional, Sequence

algorithms_guaranteed: Sequence[str]
algorithms_available: Sequence[str]

class Hash:
    def __init__(
        self,
        name: str,
        buffer: Optional[bytes] = None,
        *,
        block_size: int = ...,
    ) -> None: ...
    def update(self, buffer: bytes) -> None: ...
    def copy(self) -> Hash: ...

class Hmac:
    def __init__(
        self,
        key: bytes,
        name: str,
        buffer: Optional[bytes] = None,
        *,
        block_size: int,
    ) -> None: ...
    def update(self, buffer: bytes) -> None: ...
    def copy(self) -> Hmac: ...
