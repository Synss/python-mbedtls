# SPDX-License-Identifier: MIT
# Copyright (c) 2015, Elaborated Networks GmbH
# Copyright (c) 2018, Mathias Laurin

"""python-mbedtls is a this wrapper to ARM's mbed TLS library."""

# pylint: disable=consider-using-from-import

from __future__ import annotations

import mbedtls.cipher as cipher
import mbedtls.exceptions as exceptions
import mbedtls.hashlib as hashlib
import mbedtls.hkdf as hkdf
import mbedtls.hmac as hmac
import mbedtls.pk as pk
import mbedtls.secrets as secrets
import mbedtls.tls as tls
import mbedtls.version as version
import mbedtls.x509 as x509

if version.has_feature("MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED"):
    import mbedtls.ecjpake as ecjpake

__version__ = "2.6.1"

from typing import Tuple

__all__: Tuple[str, ...] = (
    "cipher",
    "exceptions",
    "hashlib",
    "hkdf",
    "hmac",
    "pk",
    "secrets",
    "tls",
    "version",
    "x509",
)

if version.has_feature("MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED"):
    __all__ = __all__ + ("ecjpake",)


has_feature = version.has_feature
