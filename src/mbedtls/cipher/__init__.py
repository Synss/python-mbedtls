# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""The cipher package provide symmetric encryption and decryption.

The API follows the recommendations from PEP 272 "API for Block
Encryption Algorithms"

"""

from ._cipher import *
from . import AES
from . import ARC4
from . import ARIA
from . import Blowfish
from . import Camellia
from . import DES
from . import DES3
from . import DES3dbl
from . import CHACHA20


__all__ = _cipher.__all__ + (
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
