#!/usr/bin/env python
# SPDX-License-Identifier: MIT
"""An example DTLS/TLS client.

Run ./programs/client.py --help.

"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from contextlib import suppress
from typing import Any, Optional, Tuple, Union

from mbedtls._tls import _enable_debug_output, _set_debug_level  # type: ignore
from mbedtls.exceptions import TLSError
from mbedtls.tls import (
    ClientContext,
    DTLSConfiguration,
    TLSConfiguration,
    TLSWrappedSocket,
)

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

if sys.version_info < (3, 8):
    from typing_extensions import Final
else:
    from typing import Final


__all__ = ["Client"]

_Address: TypeAlias = Union[Tuple[Any, ...], str]


def _echo_tls(sock: TLSWrappedSocket, buffer: bytes, chunksize: int) -> bytes:
    view = memoryview(buffer)
    received = bytearray()
    for idx in range(0, len(view), chunksize):
        part = view[idx : idx + chunksize]
        sock.send(part)
        received += sock.recv(chunksize)
    return received


def _echo_dtls(sock: TLSWrappedSocket, buffer: bytes, chunksize: int) -> bytes:
    view = memoryview(buffer)
    received = bytearray()
    while len(received) != len(buffer):
        part = view[len(received) : len(received) + chunksize]
        sock.send(part)
        data, _addr = sock.recvfrom(chunksize)
        received += data
        if not data:
            # Avoid tight loop.
            time.sleep(0.01)
    return received


class Client:
    def __init__(
        self,
        cli_conf: Union[TLSConfiguration, DTLSConfiguration],
        proto: socket.SocketKind,
        srv_address: _Address,
        srv_hostname: Optional[str],
    ) -> None:
        super().__init__()
        self.cli_conf: Final = cli_conf
        self.proto: Final = proto
        self.srv_address: Final = srv_address
        self.srv_hostname: Final = srv_hostname
        self._sock: Optional[TLSWrappedSocket] = None
        self._echo: Final = {
            socket.SOCK_STREAM: _echo_tls,
            socket.SOCK_DGRAM: _echo_dtls,
        }[self.proto]

    def __enter__(self) -> Client:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def __del__(self) -> None:
        self.stop()

    @property
    def context(self) -> Optional[ClientContext]:
        if self._sock is None:
            return None
        assert isinstance(self._sock.context, ClientContext)
        return self._sock.context

    def do_handshake(self) -> None:
        if not self._sock:
            return

        self._sock.do_handshake()

    def echo(self, buffer: bytes, chunksize: int) -> bytes:
        if not self._sock:
            return b""

        return bytes(self._echo(self._sock, buffer, chunksize))

    def start(self) -> None:
        if self._sock:
            self.stop()

        self._sock = ClientContext(self.cli_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto),
            server_hostname=self.srv_hostname,
        )
        self._sock.connect(self.srv_address)

    def stop(self) -> None:
        if not self._sock:
            return

        with suppress(TLSError, OSError):
            self._sock.close()
        self._sock = None

    def restart(self) -> None:
        self.stop()
        self.start()


def parse_args() -> argparse.Namespace:
    class PSKArg(argparse.Action):
        def __call__(
            self,
            parser: object,
            namespace: argparse.Namespace,
            values: Any,
            option_string: Optional[str] = None,
        ) -> None:
            def entry(kv: bytes) -> Tuple[str, bytes]:
                k, v = kv.split(b"=")
                return k.decode("utf-8"), v

            setattr(namespace, self.dest, entry(values))

    parser = argparse.ArgumentParser(description="client")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--tls", dest="proto", action="store_const", const=socket.SOCK_STREAM
    )
    group.add_argument(
        "--dtls", dest="proto", action="store_const", const=socket.SOCK_DGRAM
    )
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", default=4433, type=int)
    parser.add_argument("--debug", type=int)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument(
        "--psk",
        type=lambda x: x.encode("latin1"),
        action=PSKArg,
        metavar="CLI=SECRET",
    )
    parser.add_argument("message", default="hello")
    return parser.parse_args()


def main(args: argparse.Namespace) -> None:
    conf: Union[TLSConfiguration, DTLSConfiguration]
    if args.proto is socket.SOCK_STREAM:
        conf = TLSConfiguration(
            pre_shared_key=args.psk, validate_certificates=False
        )
    elif args.proto is socket.SOCK_DGRAM:
        conf = DTLSConfiguration(
            pre_shared_key=args.psk, validate_certificates=False
        )
    else:
        raise NotImplementedError(args.proto)

    with Client(
        conf, args.proto, (args.address, args.port), args.server_name
    ) as cli:
        if args.debug is not None:
            _enable_debug_output(cli.context)
            _set_debug_level(args.debug)

        cli.do_handshake()
        received = cli.echo(args.message.encode("utf-8"), 1024)
    print(received.decode("utf-8"))


if __name__ == "__main__":
    main(parse_args())
