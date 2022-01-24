#!/usr/bin/env python
"""An example DTLS/TLS server.

Run ./programs/server.py --help.

"""

import argparse
import socket
import time
from contextlib import suppress
from functools import partial

from mbedtls._tls import _enable_debug_output, _set_debug_level
from mbedtls.exceptions import TLSError
from mbedtls.tls import (
    DTLSConfiguration,
    HelloVerifyRequest,
    ServerContext,
    TLSConfiguration,
)

__all__ = ["Server"]


def _make_tls_connection(sock):
    assert sock
    conn, _addr = sock.accept()
    conn.do_handshake()
    return conn


def _make_dtls_connection(sock):
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
    def __init__(self, srv_conf, proto, address):
        super().__init__()
        self.srv_conf = srv_conf
        self.proto = proto
        self.address = address
        self._make_connection = {
            socket.SOCK_STREAM: _make_tls_connection,
            socket.SOCK_DGRAM: _make_dtls_connection,
        }[self.proto]
        self._sock = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()

    def __del__(self):
        self.stop()

    @property
    def context(self):
        if self._sock is None:
            return None
        return self._sock.context

    def start(self):
        if self._sock:
            self.stop()

        self._sock = ServerContext(self.srv_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto)
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self.address)
        if self.proto is socket.SOCK_STREAM:
            self._sock.listen(1)

    def stop(self):
        if not self._sock:
            return

        self._sock.close()
        self._sock = None

    def run(self, conn_handler):
        if not self._sock:
            raise ConnectionRefusedError("server not started")

        while True:
            self._run(conn_handler)

    def _run(self, conn_handler):
        with self._make_connection(self._sock) as conn:
            conn_handler(conn)


def echo_handler(conn, *, packet_size):
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


def parse_args():
    class PSKStoreArg(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            def entry(kv):
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


def main(args):
    conf = {
        socket.SOCK_STREAM: TLSConfiguration,
        socket.SOCK_DGRAM: DTLSConfiguration,
    }[args.proto](
        pre_shared_key_store=args.psk_store,
        validate_certificates=False,
    )

    if args.debug is not None:
        _enable_debug_output(conf)
        _set_debug_level(args.debug)

    with Server(conf, args.proto, (args.address, args.port)) as srv:
        srv.run(partial(echo_handler, packet_size=4069))


if __name__ == "__main__":
    import faulthandler

    faulthandler.enable()
    with suppress(KeyboardInterrupt):
        main(parse_args())
