#!/usr/bin/env python3
"""Disposable namespace test TCP echo fixture, not a network-facing service."""
import argparse
import pathlib
import socket
import time


def mark(path, value):
    pathlib.Path(path).write_text(value, encoding="ascii")


def server(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("198.18.0.2", 18888))
        sock.listen(1)
        mark(args.ready, "ready")
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(12)
            while True:
                try:
                    payload = conn.recv(4)
                except (socket.timeout, ConnectionError):
                    return
                if not payload:
                    return
                conn.sendall(b"ACK!")


def client(args):
    with socket.create_connection(("198.18.0.2", 18888), timeout=4) as sock:
        sock.settimeout(3)
        sock.sendall(b"PING")
        if sock.recv(4) != b"ACK!":
            raise RuntimeError("initial TCP handshake failed")
        mark(args.ready, "connected")
        end = time.monotonic() + 12
        while not pathlib.Path(args.trigger).exists():
            if time.monotonic() >= end:
                raise TimeoutError("revocation trigger never arrived")
            time.sleep(0.05)
        try:
            sock.sendall(b"PING")
            response = sock.recv(4)
        except (socket.timeout, ConnectionError, OSError):
            mark(args.result, "blocked")
            return
        mark(args.result, "bypass" if response == b"ACK!" else "blocked")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--ready", required=True)
    parser.add_argument("--trigger")
    parser.add_argument("--result")
    args = parser.parse_args()
    if args.mode == "server":
        server(args)
    else:
        if not args.trigger or not args.result:
            parser.error("client requires --trigger and --result")
        client(args)


if __name__ == "__main__":
    main()
