# SPDX-License-Identifier: MIT
# Copyright (c) 2016, Elaborated Networks GmbH
# Copyright (c) 2019, Mathias Laurin

"""The cipher package provide symmetric encryption and decryption.

The API follows the recommendations from PEP 272 "API for Block
Encryption Algorithms"

"""

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
from ._cipher import (  # type: ignore
    AEADCipher,
    Cipher,
    Mode,
    get_supported_ciphers,
)

# Add module-level aliases to comply with PEP 272.
MODE_ECB = Mode.ECB
MODE_CBC = Mode.CBC
MODE_CFB = Mode.CFB
MODE_OFB = Mode.OFB
MODE_CTR = Mode.CTR
MODE_GCM = Mode.GCM
MODE_STREAM = Mode.STREAM
MODE_CCM = Mode.CCM
MODE_XTS = Mode.XTS
MODE_CHACHAPOLY = Mode.CHACHAPOLY


__all__ = (
    "AEADCipher",
    "AES",
    "ARC4",
    "ARIA",
    "Blowfish",
    "Camellia",
    "Cipher",
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
