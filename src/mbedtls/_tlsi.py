# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

"""Interfaces defined in PEP 543 (+ DTLS)."""

from __future__ import annotations

import enum
import sys
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple, TypeVar, Union

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal

__all__ = ["NextProtocol", "TLSVersion", "DTLSVersion"]


@enum.unique
class NextProtocol(enum.Enum):
    H2: bytes = b"h2"
    H2C: bytes = b"h2c"
    HTTP1: bytes = b"http/1.1"
    WEBRTC: bytes = b"webrtc"
    C_WEBRTC: bytes = b"c-webrtc"
    FTP: bytes = b"ftp"
    STUN: bytes = b"stun.nat-discovery"
    TURN: bytes = b"stun.turn"


class TLSVersion(enum.Enum):
    # PEP 543
    MINIMUM_SUPPORTED = enum.auto()
    SSLv2 = enum.auto()
    SSLv3 = enum.auto()
    TLSv1 = enum.auto()
    TLSv1_1 = enum.auto()
    TLSv1_2 = enum.auto()
    TLSv1_3 = enum.auto()
    MAXIMUM_SUPPORTED = enum.auto()


class DTLSVersion(enum.Enum):
    MINIMUM_SUPPORTED = enum.auto()
    DTLSv1_0 = enum.auto()
    DTLSv1_2 = enum.auto()
    MAXIMUM_SUPPORTED = enum.auto()


TrustStore = object
Certificate = object
PrivateKey = object
CipherSuite = object
DEFAULT_CIPHER_LIST = ()

ServerNameCallback = object


class __DefaultValue(enum.Enum):
    DEFAULT_VALUE = enum.auto()


_DEFAULT_VALUE = __DefaultValue.DEFAULT_VALUE

T = TypeVar("T")
_Wrap = Union[T, Literal[__DefaultValue.DEFAULT_VALUE]]


def _unwrap(x: _Wrap[T], default: T) -> T:
    if x is _DEFAULT_VALUE:
        return default
    return x


_CertificateChain = Tuple[Tuple[Certificate, ...], PrivateKey]
_Ciphers = Tuple[Union[CipherSuite, int], ...]
_InnerProtocols = Tuple[Union[NextProtocol, bytes], ...]


@dataclass(frozen=True)
class TLSConfiguration:
    validate_certificates: bool = True
    certificate_chain: Optional[_CertificateChain] = None
    ciphers: Optional[_Ciphers] = None
    inner_protocols: Optional[_InnerProtocols] = None
    lowest_supported_version: TLSVersion = TLSVersion.TLSv1
    highest_supported_version: TLSVersion = TLSVersion.MAXIMUM_SUPPORTED
    trust_store: Optional[TrustStore] = None
    sni_callback: Optional[ServerNameCallback] = None
    pre_shared_key: Optional[Tuple[str, bytes]] = None
    pre_shared_key_store: Mapping[str, bytes] = field(default_factory=dict)

    def update(
        self,
        validate_certificates: _Wrap[bool] = _DEFAULT_VALUE,
        certificate_chain: _Wrap[_CertificateChain] = _DEFAULT_VALUE,
        ciphers: _Wrap[_Ciphers] = _DEFAULT_VALUE,
        inner_protocols: _Wrap[_InnerProtocols] = _DEFAULT_VALUE,
        lowest_supported_version: _Wrap[TLSVersion] = _DEFAULT_VALUE,
        highest_supported_version: _Wrap[TLSVersion] = _DEFAULT_VALUE,
        trust_store: _Wrap[TrustStore] = _DEFAULT_VALUE,
        sni_callback: _Wrap[Optional[ServerNameCallback]] = _DEFAULT_VALUE,
        pre_shared_key: _Wrap[Tuple[str, bytes]] = _DEFAULT_VALUE,
        pre_shared_key_store: _Wrap[Mapping[str, bytes]] = _DEFAULT_VALUE,
    ) -> TLSConfiguration:
        """
        Create a new ``TLSConfiguration``, overriding some of the settings
        on the original configuration with the new settings.
        """
        return self.__class__(
            _unwrap(validate_certificates, self.validate_certificates),
            _unwrap(certificate_chain, self.certificate_chain),
            _unwrap(ciphers, self.ciphers),
            _unwrap(inner_protocols, self.inner_protocols),
            _unwrap(lowest_supported_version, self.lowest_supported_version),
            _unwrap(highest_supported_version, self.highest_supported_version),
            _unwrap(trust_store, self.trust_store),
            _unwrap(sni_callback, self.sni_callback),
            _unwrap(pre_shared_key, self.pre_shared_key),
            _unwrap(pre_shared_key_store, self.pre_shared_key_store),
        )


@dataclass(frozen=True)
class DTLSConfiguration:
    validate_certificates: bool = True
    certificate_chain: Optional[_CertificateChain] = None
    ciphers: Optional[_Ciphers] = None
    inner_protocols: Optional[_InnerProtocols] = None
    lowest_supported_version: DTLSVersion = DTLSVersion.DTLSv1_0
    highest_supported_version: DTLSVersion = DTLSVersion.MAXIMUM_SUPPORTED
    trust_store: Optional[TrustStore] = None
    anti_replay: bool = True
    handshake_timeout_min: float = 1.0
    handshake_timeout_max: float = 60.0
    sni_callback: Optional[ServerNameCallback] = None
    pre_shared_key: Optional[Tuple[str, bytes]] = None
    pre_shared_key_store: Mapping[str, bytes] = field(default_factory=dict)

    def update(
        self,
        validate_certificates: _Wrap[bool] = _DEFAULT_VALUE,
        certificate_chain: _Wrap[_CertificateChain] = _DEFAULT_VALUE,
        ciphers: _Wrap[_Ciphers] = _DEFAULT_VALUE,
        inner_protocols: _Wrap[_InnerProtocols] = _DEFAULT_VALUE,
        lowest_supported_version: _Wrap[DTLSVersion] = _DEFAULT_VALUE,
        highest_supported_version: _Wrap[DTLSVersion] = _DEFAULT_VALUE,
        trust_store: _Wrap[TrustStore] = _DEFAULT_VALUE,
        anti_replay: _Wrap[bool] = _DEFAULT_VALUE,
        handshake_timeout_min: _Wrap[float] = _DEFAULT_VALUE,
        handshake_timeout_max: _Wrap[float] = _DEFAULT_VALUE,
        sni_callback: _Wrap[ServerNameCallback] = _DEFAULT_VALUE,
        pre_shared_key: _Wrap[Tuple[str, bytes]] = _DEFAULT_VALUE,
        pre_shared_key_store: _Wrap[Mapping[str, bytes]] = _DEFAULT_VALUE,
    ) -> DTLSConfiguration:
        """
        Create a new ``TLSConfiguration``, overriding some of the settings
        on the original configuration with the new settings.
        """
        return self.__class__(
            _unwrap(validate_certificates, self.validate_certificates),
            _unwrap(certificate_chain, self.certificate_chain),
            _unwrap(ciphers, self.ciphers),
            _unwrap(inner_protocols, self.inner_protocols),
            _unwrap(lowest_supported_version, self.lowest_supported_version),
            _unwrap(highest_supported_version, self.highest_supported_version),
            _unwrap(trust_store, self.trust_store),
            _unwrap(anti_replay, self.anti_replay),
            _unwrap(handshake_timeout_min, self.handshake_timeout_min),
            _unwrap(handshake_timeout_max, self.handshake_timeout_max),
            _unwrap(sni_callback, self.sni_callback),
            _unwrap(pre_shared_key, self.pre_shared_key),
            _unwrap(pre_shared_key_store, self.pre_shared_key_store),
        )
