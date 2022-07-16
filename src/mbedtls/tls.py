# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

from __future__ import annotations

import enum
import socket as _pysocket
import struct
import sys
from typing import Any, NoReturn, Optional, Tuple, Union, cast

from ._tls import HandshakeStep as HandshakeStep
from ._tls import HelloVerifyRequest
from ._tls import MbedTLSBuffer as TLSWrappedBuffer
from ._tls import (
    Purpose,
    RaggedEOF,
    TLSSession,
    TrustStore,
    WantReadError,
    WantWriteError,
    _BaseContext,
    _tls_from_version,
    _tls_to_version,
    ciphers_available,
)
from ._tlsi import DTLSConfiguration as DTLSConfiguration
from ._tlsi import DTLSVersion as DTLSVersion
from ._tlsi import NextProtocol as NextProtocol
from ._tlsi import PrivateKey as PrivateKey
from ._tlsi import ServerNameCallback as ServerNameCallback
from ._tlsi import TLSConfiguration as TLSConfiguration
from ._tlsi import TLSVersion as TLSVersion

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias


__all__ = (
    "ClientContext",
    "DTLSConfiguration",
    "DTLSVersion",
    "HelloVerifyRequest",
    "NextProtocol",
    "PrivateKey",
    "Purpose",
    "RaggedEOF",
    "ServerContext",
    "ServerNameCallback",
    "TLSConfiguration",
    "TLSRecordHeader",
    "TLSSession",
    "TLSVersion",
    "TLSWrappedBuffer",
    "TLSWrappedSocket",
    "TrustStore",
    "WantReadError",
    "WantWriteError",
    "ciphers_available",
)

# Stolen from `_socket.pyi`.
_Address: TypeAlias = Union[Tuple[Any, ...], str]


class TLSRecordHeader:
    """Encode/decode TLS record protocol format."""

    __slots__ = ("record_type", "version", "length")
    fmt = "!BHH"

    class RecordType(enum.IntEnum):
        CHANGE_CIPHER_SPEC = 0x14
        ALERT = 0x15
        HANDSHAKE = 0x16
        APPLICATION_DATA = 0x17

    def __init__(
        self,
        record_type: Union[int, TLSRecordHeader.RecordType],
        version: Union[int, Tuple[int, int], TLSVersion],
        length: int,
    ) -> None:
        def parse_version(
            v: Union[int, Tuple[int, int], TLSVersion]
        ) -> TLSVersion:
            if isinstance(v, TLSVersion):
                return v
            if isinstance(v, int):
                return TLSVersion(v)
            return TLSVersion(((v[0] & 0xFF) << 8) + v[1] & 0xFF)

        self.record_type: Final = TLSRecordHeader.RecordType(record_type)
        self.version: Final = parse_version(version)
        self.length: Final = length

    def __str__(self) -> str:
        return "%s(%s, %s, %s)" % (
            type(self).__name__,
            self.record_type,
            self.version,
            self.length,
        )

    def __repr__(self) -> str:
        return "%s(%r, %r, %r)" % (
            type(self).__name__,
            self.record_type,
            self.version,
            self.length,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TLSRecordHeader):
            return NotImplemented
        return (
            self.record_type is other.record_type
            and self.version is other.version
            and self.length == other.length
        )

    def __hash__(self) -> int:
        return 0x5AFE ^ self.record_type ^ self.version.value ^ self.length

    def __len__(self) -> int:
        return 5

    def __bytes__(self) -> bytes:
        maj, min = _tls_from_version(self.version)
        version = ((maj & 0xFF) << 8) + (min & 0xFF)
        return struct.pack(
            TLSRecordHeader.fmt,
            self.record_type,
            version,
            self.length,
        )

    @classmethod
    def from_bytes(cls, header: bytes) -> TLSRecordHeader:
        record_type, maj_min_version, length = struct.unpack(
            TLSRecordHeader.fmt, header[:5]
        )
        maj, min = (maj_min_version >> 8) & 0xFF, maj_min_version & 0xFF
        return cls(
            TLSRecordHeader.RecordType(record_type),
            _tls_to_version((maj, min)),
            length,
        )


class ClientContext(_BaseContext):
    # _pep543.ClientContext

    @property
    def _purpose(self) -> Purpose:
        return Purpose.CLIENT_AUTH

    def wrap_socket(
        self, socket: _pysocket.socket, server_hostname: Optional[str]
    ) -> TLSWrappedSocket:
        """Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        Args:
            socket: The socket to wrap.
            server_hostname: The hostname of the service
                which we are connecting to.  Pass ``None`` if hostname
                validation is not desired.  This parameter has no
                default value because opting-out hostname validation is
                dangerous and should not be the default behavior.

        """
        buffer = self.wrap_buffers(server_hostname)
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self, server_hostname: Optional[str]) -> TLSWrappedBuffer:
        """Create an in-memory stream for TLS."""
        # PEP 543
        return TLSWrappedBuffer(self, server_hostname)


class ServerContext(_BaseContext):
    # _pep543.ServerContext

    @property
    def _purpose(self) -> Purpose:
        return Purpose.SERVER_AUTH

    def wrap_socket(self, socket: _pysocket.socket) -> TLSWrappedSocket:
        """Wrap an existing Python socket object ``socket``."""
        buffer = self.wrap_buffers()
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self) -> TLSWrappedBuffer:
        # PEP 543
        return TLSWrappedBuffer(self)


class TLSWrappedSocket:
    # _pep543.TLSWrappedSocket
    def __init__(
        self, socket: _pysocket.socket, buffer: TLSWrappedBuffer
    ) -> None:
        super().__init__()
        self._socket = socket
        self._buffer = buffer
        self._context = buffer.context
        self._closed = False

    @property
    def context(self) -> _BaseContext:
        return self._buffer.context

    @property
    def _buffer(self) -> TLSWrappedBuffer:
        return cast(TLSWrappedBuffer, self.__dict__["_buffer"])

    @_buffer.setter
    def _buffer(self, __buffer: TLSWrappedBuffer) -> None:
        self.__dict__["_buffer"] = __buffer
        self.setcookieparam = __buffer.setcookieparam
        self.cipher = __buffer.cipher
        self.negotiated_protocol = __buffer.negotiated_protocol
        self.negotiated_tls_version = __buffer.negotiated_tls_version

    @property
    def _socket(self) -> _pysocket.socket:
        return cast(_pysocket.socket, self.__dict__["_socket"])

    @_socket.setter
    def _socket(self, __socket: _pysocket.socket) -> None:
        self.__dict__["_socket"] = __socket
        # PEP 543 requires the full socket API.
        self.family = __socket.family
        self.proto = __socket.proto
        self.type = __socket.type
        self.bind = __socket.bind
        self.connect = __socket.connect
        self.connect_ex = __socket.connect_ex
        self.fileno = __socket.fileno
        self.getpeername = __socket.getpeername
        self.getsockname = __socket.getsockname
        self.getsockopt = __socket.getsockopt
        self.listen = __socket.listen
        self.makefile = __socket.makefile
        self.setblocking = __socket.setblocking
        self.settimeout = __socket.settimeout
        self.gettimeout = __socket.gettimeout
        self.setsockopt = __socket.setsockopt

    def __getstate__(self) -> NoReturn:
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __enter__(self) -> TLSWrappedSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        if not self._closed:
            self.close()

    def __str__(self) -> str:
        return str(self._socket)

    @property
    def _handshake_state(self) -> HandshakeStep:
        return self._buffer._handshake_state

    def accept(self) -> Tuple[TLSWrappedSocket, _Address]:
        if self.type == _pysocket.SOCK_STREAM:
            conn, address = self._socket.accept()
        else:
            _, address = self._socket.recvfrom(1024, _pysocket.MSG_PEEK)
            # Use this socket to communicate with the client and bind
            # another one for the next connection.  This procedure is
            # adapted from `mbedtls_net_accept()`.
            sockname = self.getsockname()
            conn = _pysocket.fromfd(self.fileno(), self.family, self.type)
            conn.connect(address)
            # Closing the socket on Python 2.7 and 3.4 invalidates
            # the accessors.  So we should get the values first.
            family, type_, proto = self.family, self.type, self.proto
            self.close()
            self._socket = _pysocket.socket(family, type_, proto)
            self.setsockopt(_pysocket.SOL_SOCKET, _pysocket.SO_REUSEADDR, 1)
            self.bind(sockname)
        if isinstance(self.context, ClientContext):
            # Probably not very useful but there is not reason to forbid it.
            return (
                self.context.wrap_socket(conn, self._buffer._server_hostname),
                address,
            )
        assert isinstance(self.context, ServerContext)
        return self.context.wrap_socket(conn), address

    def close(self) -> None:
        self._closed = True
        self._buffer.shutdown()
        self._socket.close()

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        encrypted = self._socket.recv(bufsize, flags)
        if not encrypted:
            return b""
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize)

    def recv_into(
        self, buffer: bytes, nbytes: Optional[int] = None, flags: int = 0
    ) -> None:
        raise NotImplementedError

    def recvfrom(self, bufsize: int, flags: int = 0) -> Tuple[bytes, _Address]:
        encrypted, addr = self._socket.recvfrom(bufsize, flags)
        if not encrypted:
            return b"", addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize), addr

    def recvfrom_into(
        self, buffer: bytes, nbytes: Optional[int] = None, flags: int = 0
    ) -> Tuple[int, _Address]:
        encrypted, addr = self._socket.recvfrom(
            nbytes if nbytes is not None else len(buffer), flags
        )
        if not encrypted:
            return 0, addr
        self._buffer.receive_from_network(encrypted)
        return (
            self._buffer.readinto(
                buffer, nbytes if nbytes is not None else len(buffer)
            ),
            addr,
        )

    def send(self, message: bytes, flags: int = 0) -> int:
        # Maximum size supported by TLS is 16K (encrypted).
        # mbedTLS defines it in MBEDTLS_SSL_MAX_CONTENT_LEN and
        # MBEDTLS_SSL_IN_CONTENT_LEN/MBEDTLS_SSL_OUT_CONTENT_LEN.
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._socket.send(encrypted, flags)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def sendall(self, message: bytes, flags: int = 0) -> None:
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._buffer.consume_outgoing(amt)
        self._socket.sendall(encrypted)

    def sendto(  # type: ignore[no-untyped-def]
        self, message: bytes, *args
    ) -> int:
        if not 1 <= len(args) <= 2:
            raise TypeError(
                "sendto() takes 2 or 3 arguments (%i given)" % (1 + len(args))
            )
        if len(args) == 1:
            flags, address = 0, args[0]
        else:
            flags, address = args

        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        if flags:
            self._socket.sendto(encrypted, flags, address)
        else:
            self._socket.sendto(encrypted, address)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def shutdown(self, how: int) -> None:
        self._buffer.shutdown()
        self._socket.shutdown(how)

    # PEP 543 adds the following methods.

    def do_handshake(self) -> None:
        while self._handshake_state is not HandshakeStep.HANDSHAKE_OVER:
            try:
                self._buffer.do_handshake()
            except WantReadError:
                data = self._socket.recv(1024)
                self._buffer.receive_from_network(data)
            except WantWriteError:
                in_transit = self._buffer.peek_outgoing(1024)
                amt = self._socket.send(in_transit)
                self._buffer.consume_outgoing(amt)

    def unwrap(self) -> _pysocket.socket:
        self._buffer.shutdown()
        return self._socket
