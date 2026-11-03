#!/usr/bin/env python3
"""TCP probe proving blocked delivery and same-socket recovery in disposable netns."""
import argparse
import pathlib
import socket
import time


def mark(path, value):
    pathlib.Path(path).write_text(value, encoding="ascii")


def await_file(path, seconds=15):
    deadline = time.monotonic() + seconds
    while not pathlib.Path(path).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("missing synchronization marker: " + path)
        time.sleep(0.02)


def server(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("198.18.0.2", 18888))
        listener.listen(1)
        listener.settimeout(15)
        mark(args.ready, "listening")
        with listener.accept()[0] as conn:
            conn.settimeout(30)
            # Precisely two 4-byte messages on one connection.
            for index in (1, 2):
                data = conn.recv(4)
                if data != b"PING":
                    raise RuntimeError("unexpected payload on server: " + repr(data))
                mark(args.ready + "." + str(index), "received")
                conn.sendall(b"ACK!")


def client(args):
    with socket.create_connection(("198.18.0.2", 18888), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"PING")
        if sock.recv(4) != b"ACK!":
            raise RuntimeError("initial echo failed")
        mark(args.ready, "connected")
        await_file(args.trigger)
        sock.sendall(b"PING")
        sock.settimeout(2)
        try:
            response = sock.recv(4)
        except socket.timeout:
            mark(args.result, "timeout")
        else:
            raise RuntimeError("post-revocation read did not time out: " + repr(response))
        await_file(args.resume)
        sock.settimeout(12)
        if sock.recv(4) != b"ACK!":
            raise RuntimeError("same-socket recovery did not receive ACK")
        mark(args.result, "recovered")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--ready", required=True)
    parser.add_argument("--trigger")
    parser.add_argument("--result")
    parser.add_argument("--resume")
    args = parser.parse_args()
    if args.mode == "server":
        server(args)
    else:
        if not args.trigger or not args.result or not args.resume:
            parser.error("client requires trigger, result, and resume")
        client(args)


if __name__ == "__main__":
    main()
