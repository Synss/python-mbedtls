# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Mathias Laurin

from __future__ import annotations

import enum
import sys
from collections import abc
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple, Union, overload

from mbedtls.pk import ECC, RSA
from mbedtls.x509 import CRT

if sys.version_info < (3, 8):
    from typing_extensions import Literal
else:
    from typing import Literal

def ciphers_available() -> Sequence[str]: ...
@enum.unique
class NextProtocol(enum.Enum):
    H2: bytes
    H2C: bytes
    HTTP1: bytes
    WEBRTC: bytes
    C_WEBRTC: bytes
    FTP: bytes
    STUN: bytes
    TURN: bytes

class TLSVersion(enum.IntEnum):
    TLSv1: int
    TLSv1_1: int
    TLSv1_2: int
    TLSv1_3: int
    MINIMUM_SUPPORTED: int
    MAXIMUM_SUPPORTED: int
    @classmethod
    def from_major_minor(cls, major: int, minor: int) -> TLSVersion: ...
    def major(self) -> int: ...
    def minor(self) -> int: ...

class DTLSVersion(enum.IntEnum):
    DTLSv1_0: int
    DTLSv1_2: int
    MINIMUM_SUPPORTED: int
    MAXIMUM_SUPPORTED: int

    @classmethod
    def from_major_minor(cls, major: int, minor: int) -> DTLSVersion: ...
    def major(self) -> int: ...
    def minor(self) -> int: ...

class HandshakeStep(enum.Enum):
    HELLO_REQUEST: int
    CLIENT_HELLO: int
    SERVER_HELLO: int
    SERVER_CERTIFICATE: int
    SERVER_KEY_EXCHANGE: int
    CERTIFICATE_REQUEST: int
    SERVER_HELLO_DONE: int
    CLIENT_CERTIFICATE: int
    CLIENT_KEY_EXCHANGE: int
    CERTIFICATE_VERIFY: int
    CLIENT_CHANGE_CIPHER_SPEC: int
    CLIENT_FINISHED: int
    SERVER_CHANGE_CIPHER_SPEC: int
    SERVER_FINISHED: int
    FLUSH_BUFFERS: int
    HANDSHAKE_WRAPUP: int
    HANDSHAKE_OVER: int
    SERVER_NEW_SESSION_TICKET: int
    SERVER_HELLO_VERIFY_REQUEST_SENT: int

class TLSError(Exception): ...
class WantWriteError(TLSError): ...
class WantReadError(TLSError): ...
class RaggedEOF(TLSError): ...
class HelloVerifyRequest(TLSError): ...

class TrustStore(abc.Sequence[CRT]):
    def __init__(
        self, db: Optional[Union[Sequence[CRT], TrustStore]] = ...
    ) -> None: ...
    @classmethod
    def system(cls) -> TrustStore: ...
    @classmethod
    def from_pem_file(cls, path: Path) -> TrustStore: ...
    def __eq__(self, other: object) -> bool: ...
    def __bool__(self) -> bool: ...
    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int) -> CRT: ...
    @overload
    def __getitem__(self, s: slice) -> TrustStore: ...
    def add(self, crt: CRT) -> None: ...

class Purpose(enum.IntEnum):
    SERVER_AUTH: int
    CLIENT_AUTH: int

_Key = Union[RSA, ECC]
Certificate = CRT
PrivateKey = _Key
CipherSuite = str
ServerNameCallback = object

class TLSConfiguration:
    # TODO: Split writer / configuration in implementation file
    #       and use frozen dataclasses for the configuration.
    def __new__(
        cls,
        validate_certificates: Optional[bool] = ...,
        certificate_chain: Optional[
            Tuple[Tuple[Certificate, ...], PrivateKey]
        ] = ...,
        ciphers: Optional[Sequence[Union[CipherSuite, int]]] = ...,
        inner_protocols: Optional[Sequence[Union[NextProtocol, bytes]]] = ...,
        lowest_supported_version: Optional[TLSVersion] = ...,
        highest_supported_version: Optional[TLSVersion] = ...,
        trust_store: Optional[TrustStore] = ...,
        sni_callback: Optional[ServerNameCallback] = ...,
        pre_shared_key: Optional[Tuple[str, bytes]] = ...,
        pre_shared_key_store: Optional[Mapping[str, bytes]] = ...,
    ) -> TLSConfiguration: ...
    def update(
        self,
        validate_certificates: Optional[bool] = ...,
        certificate_chain: Optional[
            Tuple[Tuple[Certificate, ...], PrivateKey]
        ] = ...,
        ciphers: Optional[Sequence[Union[CipherSuite, int]]] = ...,
        inner_protocols: Optional[Sequence[Union[NextProtocol, bytes]]] = ...,
        lowest_supported_version: Optional[TLSVersion] = ...,
        highest_supported_version: Optional[TLSVersion] = ...,
        trust_store: Optional[TrustStore] = ...,
        sni_callback: Optional[ServerNameCallback] = ...,
        pre_shared_key: Optional[Tuple[str, bytes]] = ...,
        pre_shared_key_store: Optional[Mapping[str, bytes]] = ...,
    ) -> TLSConfiguration: ...
    validate_certificates: Optional[bool]
    certificate_chain: Optional[Tuple[Tuple[Certificate, ...], PrivateKey]]
    ciphers: Optional[Tuple[Union[CipherSuite, int]]]
    inner_protocols: Optional[Tuple[Union[NextProtocol, bytes]]]
    lowest_supported_version: Optional[TLSVersion]
    highest_supported_version: Optional[TLSVersion]
    trust_store: Optional[TrustStore]
    sni_callback: Optional[ServerNameCallback]
    pre_shared_key: Optional[Tuple[str, bytes]]
    pre_shared_key_store: Optional[Mapping[str, bytes]]

class DTLSConfiguration:
    def __new__(
        cls,
        validate_certificates: Optional[bool] = ...,
        certificate_chain: Optional[
            Tuple[Tuple[Certificate, ...], PrivateKey]
        ] = ...,
        ciphers: Optional[Sequence[Union[CipherSuite, int]]] = ...,
        inner_protocols: Optional[Sequence[Union[NextProtocol, bytes]]] = ...,
        lowest_supported_version: Optional[DTLSVersion] = ...,
        highest_supported_version: Optional[DTLSVersion] = ...,
        trust_store: Optional[TrustStore] = ...,
        anti_replay: Optional[bool] = ...,
        handshake_timeout_min: Optional[int] = ...,
        handshake_timeout_max: Optional[int] = ...,
        sni_callback: Optional[ServerNameCallback] = ...,
        pre_shared_key: Optional[Tuple[str, bytes]] = ...,
        pre_shared_key_store: Optional[Mapping[str, bytes]] = ...,
    ) -> DTLSConfiguration: ...
    def update(
        self,
        validate_certificates: Optional[bool] = ...,
        certificate_chain: Optional[
            Tuple[Tuple[Certificate, ...], PrivateKey]
        ] = ...,
        ciphers: Optional[Sequence[Union[CipherSuite, int]]] = ...,
        inner_protocols: Optional[Sequence[Union[NextProtocol, bytes]]] = ...,
        lowest_supported_version: Optional[DTLSVersion] = ...,
        highest_supported_version: Optional[DTLSVersion] = ...,
        trust_store: Optional[TrustStore] = ...,
        anti_replay: Optional[bool] = ...,
        handshake_timeout_min: Optional[int] = ...,
        handshake_timeout_max: Optional[int] = ...,
        sni_callback: Optional[ServerNameCallback] = ...,
        pre_shared_key: Optional[Tuple[str, bytes]] = ...,
        pre_shared_key_store: Optional[Mapping[str, bytes]] = ...,
    ) -> DTLSConfiguration: ...
    validate_certificates: Optional[bool]
    certificate_chain: Optional[Tuple[Tuple[Certificate], PrivateKey]]
    ciphers: Optional[Tuple[Union[CipherSuite, int]]]
    inner_protocols: Optional[Tuple[Union[NextProtocol, bytes]]]
    lowest_supported_version: Optional[DTLSVersion]
    highest_supported_version: Optional[DTLSVersion]
    trust_store: Optional[TrustStore]
    anti_replay: Optional[bool]
    handshake_timeout_min: Optional[int]
    handshake_timeout_max: Optional[int]
    sni_callback: Optional[ServerNameCallback]
    pre_shared_key: Optional[Tuple[str, bytes]]
    pre_shared_key_store: Optional[Mapping[str, bytes]]

class _BaseContext:
    def __init__(
        self, configuration: Union[TLSConfiguration, DTLSConfiguration]
    ) -> None: ...
    def __eq__(self, other: object) -> bool: ...
    @property
    def configuration(self) -> Union[TLSConfiguration, DTLSConfiguration]: ...
    @property
    def _purpose(self) -> Purpose: ...

class MbedTLSBuffer:
    def __init__(
        self, context: _BaseContext, server_hostname: Optional[str] = None
    ) -> None: ...
    @property
    def _input_buffer(self) -> bytes: ...
    @property
    def _output_buffer(self) -> bytes: ...
    @property
    def context(self) -> _BaseContext: ...
    @property
    def _server_hostname(self) -> str: ...
    def shutdown(self) -> None: ...
    def setcookieparam(self, info: bytes) -> None: ...
    def read(self, amt: int) -> bytes: ...
    def readinto(self, buffer: bytes, amt: int) -> int: ...
    def write(self, buffer: bytes) -> int: ...
    def receive_from_network(self, data: bytes) -> None: ...
    def peek_outgoing(self, amt: int) -> bytes: ...
    def consume_outgoing(self, amt: int) -> None: ...
    @overload
    def getpeercert(self, binary_form: Literal[False]) -> str: ...
    @overload
    def getpeercert(self, binary_form: Literal[True]) -> bytes: ...
    def selected_npn_protocol(self) -> None: ...
    def negotiated_protocol(self) -> str: ...
    def cipher(self) -> bytes: ...
    @property
    def _handshake_state(self) -> HandshakeStep: ...
    def do_handshake(self) -> None: ...
    def negotiated_tls_version(self) -> Union[TLSVersion, DTLSVersion]: ...

class TLSSession: ...
