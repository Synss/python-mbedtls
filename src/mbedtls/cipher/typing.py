# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

import sys
from typing import Optional

if sys.version_info >= (3, 8):
    from typing import Protocol
else:
    from typing_extensions import Protocol

from ._cipher import AEADCipher, Cipher, Mode


class CipherType(Protocol):
    @property
    def __name__(self) -> str:
        ...

    @property
    def block_size(self) -> int:
        ...

    @property
    def key_size(self) -> int:
        ...

    def new(self, key: bytes, mode: Mode, iv: Optional[bytes]) -> Cipher:
        ...


class AEADCipherType(Protocol):
    @property
    def __name__(self) -> str:
        ...

    @property
    def block_size(self) -> int:
        ...

    @property
    def key_size(self) -> int:
        ...

    def new(
        self, key: bytes, mode: Mode, iv: Optional[bytes], ad: Optional[bytes]
    ) -> AEADCipher:
        ...
