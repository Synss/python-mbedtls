# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

"""Interfaces defined in PEP 543 (+ DTLS)."""

import enum

__all__ = ["NextProtocol"]


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
