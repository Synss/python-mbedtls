# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""The cipher package provide symmetric encryption and decryption.

The API follows the recommendations from PEP 272 "API for Block
Encryption Algorithms"

"""

import sys

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final

from . import (
    AES,
    ARC4,
    ARIA,
    CHACHA20,
    DES,
    DES3,
    Blowfish,
    Camellia,
    DES3dbl,
    typing,
)
from ._cipher import AEADCipher, Cipher, Mode, get_supported_ciphers

# Add module-level aliases to comply with PEP 272.
MODE_ECB: Final = Mode.ECB.value
MODE_CBC: Final = Mode.CBC.value
MODE_CFB: Final = Mode.CFB.value
MODE_OFB: Final = Mode.OFB.value
MODE_CTR: Final = Mode.CTR.value
MODE_GCM: Final = Mode.GCM.value
MODE_STREAM: Final = Mode.STREAM.value
MODE_CCM: Final = Mode.CCM.value
MODE_XTS: Final = Mode.XTS.value
MODE_CHACHAPOLY: Final = Mode.CHACHAPOLY.value


__all__ = (
    "AES",
    "ARC4",
    "ARIA",
    "Blowfish",
    "Camellia",
    "DES",
    "DES3",
    "DES3dbl",
    "CHACHA20",
    "get_supported_ciphers",
    "Mode",
    "MODE_ECB",
    "MODE_CBC",
    "MODE_CFB",
    "MODE_OFB",
    "MODE_CTR",
    "MODE_GCM",
    "MODE_STREAM",
    "MODE_CCM",
    "MODE_XTS",
    "MODE_CHACHAPOLY",
    "typing",
)
