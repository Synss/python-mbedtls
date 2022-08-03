#!/usr/bin/env python
# SPDX-License-Identifier: MIT
"""An example DTLS/TLS server.

Run ./programs/server.py --help.

"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from contextlib import suppress
from functools import partial
from typing import Any, Callable, NoReturn, Optional, Tuple, Union

from mbedtls._tls import _enable_debug_output, _set_debug_level  # type: ignore
from mbedtls.tls import (
    DTLSConfiguration,
    HelloVerifyRequest,
    ServerContext,
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


__all__ = ["Server"]

_Address: TypeAlias = Union[Tuple[Any, ...], str]


def _make_tls_connection(sock: TLSWrappedSocket) -> TLSWrappedSocket:
    assert sock
    conn, _addr = sock.accept()
    conn.do_handshake()
    return conn


def _make_dtls_connection(sock: TLSWrappedSocket) -> TLSWrappedSocket:
    assert sock
    conn, addr = sock.accept()
    conn.setcookieparam(addr[0].encode("ascii"))
    with suppress(HelloVerifyRequest):
        conn.do_handshake()

    _, (conn, addr) = conn, conn.accept()
    _.close()
    conn.setcookieparam(addr[0].encode("ascii"))
    conn.do_handshake()
    return conn


class Server:
    def __init__(
        self,
        srv_conf: Union[TLSConfiguration, DTLSConfiguration],
        proto: socket.SocketKind,
        address: _Address,
    ) -> None:
        super().__init__()
        self.srv_conf: Final = srv_conf
        self.proto: Final = proto
        self.address: Final = address
        self._make_connection: Final = {
            socket.SOCK_STREAM: _make_tls_connection,
            socket.SOCK_DGRAM: _make_dtls_connection,
        }[self.proto]
        self._sock: Optional[TLSWrappedSocket] = None

    def __enter__(self) -> Server:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def __del__(self) -> None:
        self.stop()

    @property
    def context(self) -> Optional[ServerContext]:
        if self._sock is None:
            return None
        assert isinstance(self._sock.context, ServerContext)
        return self._sock.context

    def start(self) -> None:
        if self._sock:
            self.stop()

        self._sock = ServerContext(self.srv_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto)
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self.address)
        if self.proto is socket.SOCK_STREAM:
            self._sock.listen(1)

    def stop(self) -> None:
        if not self._sock:
            return

        self._sock.close()
        self._sock = None

    def run(
        self, conn_handler: Callable[[TLSWrappedSocket], None]
    ) -> NoReturn:
        if not self._sock:
            raise ConnectionRefusedError("server not started")

        while True:
            self._run(conn_handler)

    def _run(self, conn_handler: Callable[[TLSWrappedSocket], None]) -> None:
        assert self._sock is not None
        with self._make_connection(self._sock) as conn:
            conn_handler(conn)


def echo_handler(conn: TLSWrappedSocket, *, packet_size: int) -> None:
    while True:
        data = conn.recv(packet_size)
        if data:
            break
        # Avoid tight loop.
        time.sleep(0.01)
    sent = 0
    view = memoryview(data)
    while sent != len(data):
        sent += conn.send(view[sent:])


def parse_args() -> argparse.Namespace:
    class PSKStoreArg(argparse.Action):
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

            setattr(
                namespace,
                self.dest,
                dict(entry(kv) for kv in values.split(b",")),
            )

    parser = argparse.ArgumentParser(description="server")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--tls", dest="proto", action="store_const", const=socket.SOCK_STREAM
    )
    group.add_argument(
        "--dtls", dest="proto", action="store_const", const=socket.SOCK_DGRAM
    )
    parser.add_argument("--address", default="0.0.0.0")
    parser.add_argument("--port", default=4433, type=int)
    parser.add_argument("--debug", type=int)
    parser.add_argument(
        "--psk-store",
        type=lambda x: x.encode("latin1"),
        action=PSKStoreArg,
        metavar="CLI1=SECRET1,CLI2=SECRET2...",
    )
    return parser.parse_args()


def main(args: argparse.Namespace) -> NoReturn:
    conf: Union[TLSConfiguration, DTLSConfiguration]
    if args.proto is socket.SOCK_STREAM:
        conf = TLSConfiguration(
            pre_shared_key_store=args.psk_store, validate_certificates=False
        )
    elif args.proto is socket.SOCK_DGRAM:
        conf = DTLSConfiguration(
            pre_shared_key_store=args.psk_store, validate_certificates=False
        )
    else:
        raise NotImplementedError(args.proto)

    with Server(conf, args.proto, (args.address, args.port)) as srv:
        if args.debug is not None:
            _enable_debug_output(srv.context)
            _set_debug_level(args.debug)

        srv.run(partial(echo_handler, packet_size=4069))


if __name__ == "__main__":
    import faulthandler

    faulthandler.enable()
    with suppress(KeyboardInterrupt):
        main(parse_args())
