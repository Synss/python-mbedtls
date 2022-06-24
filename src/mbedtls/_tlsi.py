# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

"""Interfaces defined in PEP 543 (+ DTLS)."""

import enum

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
