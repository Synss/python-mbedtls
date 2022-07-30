# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

from typing import Optional

class TLSError(Exception):
    def __init__(self, err: Optional[int] = ..., msg: str = ...) -> None: ...
    @property
    def msg(self) -> str: ...
    def __str__(self) -> str: ...
