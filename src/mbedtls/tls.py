# SPDX-License-Identifier: MIT
# Copyright (c) 2018, Mathias Laurin

import enum
import socket as _socket
import struct

from ._tls import (
    DTLSConfiguration,
    DTLSVersion,
    HandshakeStep,
    HelloVerifyRequest,
)
from ._tls import MbedTLSBuffer as TLSWrappedBuffer
from ._tls import (
    NextProtocol,
    Purpose,
    RaggedEOF,
    TLSConfiguration,
    TLSSession,
    TLSVersion,
    TrustStore,
    WantReadError,
    WantWriteError,
    _BaseContext,
    ciphers_available,
)

__all__ = (
    "ClientContext",
    "DTLSConfiguration",
    "DTLSVersion",
    "HelloVerifyRequest",
    "NextProtocol",
    "Purpose",
    "RaggedEOF",
    "ServerContext",
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


class TLSRecordHeader:
    """Encode/decode TLS record protocol format."""

    __slots__ = ("record_type", "version", "length")
    fmt = "!BHH"

    class RecordType(enum.IntEnum):
        CHANGE_CIPHER_SPEC = 0x14
        ALERT = 0x15
        HANDSHAKE = 0x16
        APPLICATION_DATA = 0x17

    def __init__(self, record_type, version, length):
        self.record_type = record_type
        self.version = version
        self.length = length

    def __str__(self):
        return "%s(%s, %s, %s)" % (
            type(self).__name__,
            self.record_type,
            self.version,
            self.length,
        )

    def __repr__(self):
        return "%s(%r, %r, %r)" % (
            type(self).__name__,
            self.record_type,
            self.version,
            self.length,
        )

    def __eq__(self, other):
        if not isinstance(other, TLSRecordHeader):
            return NotImplemented
        return (
            self.record_type is other.record_type
            and self.version is other.version
            and self.length == other.length
        )

    def __hash__(self):
        return 0x5AFE ^ self.record_type ^ self.version ^ self.length

    def __len__(self):
        return 5

    def __bytes__(self):
        return struct.pack(
            TLSRecordHeader.fmt, self.record_type, self.version, self.length
        )

    @classmethod
    def from_bytes(cls, header):
        record_type, version, length = struct.unpack(
            TLSRecordHeader.fmt, header[:5]
        )
        return cls(
            TLSRecordHeader.RecordType(record_type),
            TLSVersion(version),
            length,
        )


class ClientContext(_BaseContext):
    # _pep543.ClientContext

    @property
    def _purpose(self) -> Purpose:
        return Purpose.CLIENT_AUTH

    def wrap_socket(self, socket, server_hostname):
        """Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        Args:
            socket (socket.socket): The socket to wrap.
            server_hostname (str, optional): The hostname of the service
                which we are connecting to.  Pass ``None`` if hostname
                validation is not desired.  This parameter has no
                default value because opting-out hostname validation is
                dangerous and should not be the default behavior.

        """
        buffer = self.wrap_buffers(server_hostname)
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self, server_hostname):
        """Create an in-memory stream for TLS."""
        # PEP 543
        return TLSWrappedBuffer(self, server_hostname)


class ServerContext(_BaseContext):
    # _pep543.ServerContext

    @property
    def _purpose(self) -> Purpose:
        return Purpose.SERVER_AUTH

    def wrap_socket(self, socket):
        """Wrap an existing Python socket object ``socket``."""
        buffer = self.wrap_buffers()
        return TLSWrappedSocket(socket, buffer)

    def wrap_buffers(self):
        # PEP 543
        return TLSWrappedBuffer(self)


class TLSWrappedSocket:
    # _pep543.TLSWrappedSocket
    def __init__(self, socket, buffer):
        super().__init__()
        self._socket = socket
        self._buffer = buffer
        self._context = buffer.context
        self._closed = False

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        if not self._closed:
            self.close()

    def __str__(self):
        return str(self._socket)

    @property
    def _handshake_state(self):
        return self._buffer._handshake_state

    # PEP 543 requires the full socket API.

    @property
    def family(self):
        return self._socket.family

    @property
    def proto(self):
        return self._socket.proto

    @property
    def type(self):
        return self._socket.type

    def accept(self):
        if self.type == _socket.SOCK_STREAM:
            conn, address = self._socket.accept()
        else:
            _, address = self._socket.recvfrom(1024, _socket.MSG_PEEK)
            # Use this socket to communicate with the client and bind
            # another one for the next connection.  This procedure is
            # adapted from `mbedtls_net_accept()`.
            sockname = self.getsockname()
            conn = _socket.fromfd(self.fileno(), self.family, self.type)
            conn.connect(address)
            # Closing the socket on Python 2.7 and 3.4 invalidates
            # the accessors.  So we should get the values first.
            family, type_, proto = self.family, self.type, self.proto
            self.close()
            self._socket = _socket.socket(family, type_, proto)
            self.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            self.bind(sockname)
        return self.context.wrap_socket(conn), address

    def bind(self, address):
        self._socket.bind(address)

    def close(self):
        self._closed = True
        self._buffer.shutdown()
        self._socket.close()

    def connect(self, address):
        self._socket.connect(address)

    def connect_ex(self, address):
        self._socket.connect_ex(address)

    def fileno(self):
        return self._socket.fileno()

    def getpeername(self):
        return self._socket.getpeername()

    def getsockname(self):
        return self._socket.getsockname()

    def getsockopt(self, optname, buflen=None):
        return self._socket.getsockopt(optname, buflen=buflen)

    def listen(self, backlog=None):
        if backlog is None:
            # Use 5 (Python default) or 10 (mbedtls defaults).
            backlog = 5
        self._socket.listen(backlog)

    def makefile(self, *args, **kwargs):
        return self._socket.makefile(*args, **kwargs)

    def recv(self, bufsize, flags=0):
        encrypted = self._socket.recv(bufsize, flags)
        if not encrypted:
            return b""
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize)

    def recv_into(self, buffer, nbytes=None, flags=0):
        raise NotImplementedError

    def recvfrom(self, bufsize, flags=0):
        encrypted, addr = self._socket.recvfrom(bufsize, flags)
        if not encrypted:
            return b"", addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.read(bufsize), addr

    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        encrypted, addr = self._socket.recvfrom(len(buffer), flags)
        if not encrypted:
            return buffer, addr
        self._buffer.receive_from_network(encrypted)
        return self._buffer.readinto(buffer, nbytes), addr

    def send(self, message, flags=0):
        # Maximum size supported by TLS is 16K (encrypted).
        # mbedTLS defines it in MBEDTLS_SSL_MAX_CONTENT_LEN and
        # MBEDTLS_SSL_IN_CONTENT_LEN/MBEDTLS_SSL_OUT_CONTENT_LEN.
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._socket.send(encrypted, flags)
        self._buffer.consume_outgoing(amt)
        return len(message)

    def sendall(self, message, flags=0):
        amt = self._buffer.write(message)
        encrypted = self._buffer.peek_outgoing(amt)
        self._buffer.consume_outgoing(amt)
        self._socket.sendall(encrypted)

    def sendto(self, message, *args):
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

    def setblocking(self, flag):
        self._socket.setblocking(flag)

    def settimeout(self, value):
        self._socket.settimeout(value)

    def gettimeout(self):
        return self._socket.gettimeout()

    def setsockopt(self, level, optname, value):
        self._socket.setsockopt(level, optname, value)

    def shutdown(self, how):
        self._buffer.shutdown()
        self._socket.shutdown(how)

    # PEP 543 adds the following methods.

    def do_handshake(self):
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

    def setcookieparam(self, param):
        self._buffer.setcookieparam(param)

    def cipher(self):
        return self._buffer.cipher()

    def negotiated_protocol(self):
        return self._buffer.negotiated_protocol()

    @property
    def context(self):
        return self._buffer.context

    def negotiated_tls_version(self):
        return self._buffer.negotiated_tls_version()

    def unwrap(self):
        self._buffer.shutdown()
        return self._socket
