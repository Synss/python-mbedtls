# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""The cipher package provide symmetric encryption and decryption.

The API follows the recommendations from PEP 272 "API for Block
Encryption Algorithms"

"""

from . import AES, ARC4, ARIA, CHACHA20, DES, DES3, Blowfish, Camellia, DES3dbl
from ._cipher import *
from ._cipher import __all__ as _cipher_all

__all__ = _cipher_all + (
    "AES",
    "ARC4",
    "ARIA",
    "Blowfish",
    "Camellia",
    "DES",
    "DES3",
    "DES3dbl",
    "CHACHA20",
)
