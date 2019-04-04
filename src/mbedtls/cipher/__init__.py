"""The cipher package provide symmetric encryption and decryption.

The API follows the recommendations from PEP 272 "API for Block
Encryption Algorithms"

"""
__author__ = "Mathias Laurin"
__copyright__ = "Copyright 2016, Elaborated Networks GmbH"
__license__ = "MIT License"

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
    "AES", "ARC4", "Blowfish", "Camellia", "DES", "DES3", "DES3dbl",
    "CHACHA20")
