#!/usr/bin/env python
"""An example DTLS/TLS client.

Run ./programs/client.py --help.

"""

import argparse
import socket
import time
from contextlib import suppress

from mbedtls._tls import _enable_debug_output, _set_debug_level
from mbedtls.exceptions import TLSError
from mbedtls.tls import ClientContext, DTLSConfiguration, TLSConfiguration

__all__ = ["Client"]


def _echo_tls(sock, buffer, chunksize):
    view = memoryview(buffer)
    received = bytearray()
    for idx in range(0, len(view), chunksize):
        part = view[idx : idx + chunksize]
        _sent = sock.send(part)
        received += sock.recv(chunksize)
    return received


def _echo_dtls(sock, buffer, chunksize):
    view = memoryview(buffer)
    received = bytearray()
    while len(received) != len(buffer):
        part = view[len(received) : len(received) + chunksize]
        _sent = sock.send(part)
        data, _addr = sock.recvfrom(chunksize)
        received += data
        if not data:
            # Avoid tight loop.
            time.sleep(0.01)
    return received


class Client:
    def __init__(self, cli_conf, proto, srv_address, srv_hostname):
        super().__init__()
        self.cli_conf = cli_conf
        self.proto = proto
        self.srv_address = srv_address
        self.srv_hostname = srv_hostname
        self._sock = None
        self._echo = {
            socket.SOCK_STREAM: _echo_tls,
            socket.SOCK_DGRAM: _echo_dtls,
        }[self.proto]

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

    def do_handshake(self):
        if not self._sock:
            return

        self._sock.do_handshake()

    def echo(self, buffer, chunksize):
        if not self._sock:
            return b""

        return bytes(self._echo(self._sock, buffer, chunksize))

    def start(self):
        if self._sock:
            self.stop()

        self._sock = ClientContext(self.cli_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto),
            server_hostname=self.srv_hostname,
        )
        self._sock.connect(self.srv_address)

    def stop(self):
        if not self._sock:
            return

        with suppress(TLSError, OSError):
            self._sock.close()
        self._sock = None

    def restart(self):
        self.stop()
        self.start()


def parse_args():
    class PSKArg(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            def entry(kv):
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


def main(args):
    conf = {
        socket.SOCK_STREAM: TLSConfiguration,
        socket.SOCK_DGRAM: DTLSConfiguration,
    }[args.proto](pre_shared_key=args.psk, validate_certificates=False)

    if args.debug is not None:
        _enable_debug_output(conf)
        _set_debug_level(args.debug)

    with Client(
        conf, args.proto, (args.address, args.port), args.server_name
    ) as cli:
        cli.do_handshake()
        received = cli.echo(args.message.encode("utf-8"), 1024)
    print(received.decode("utf-8"))


if __name__ == "__main__":
    main(parse_args())
