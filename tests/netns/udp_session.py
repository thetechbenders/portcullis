#!/usr/bin/env python3
"""Established UDP reply-direction revocation/expiry probe, disposable netns only."""
import argparse
import pathlib
import socket
import time

WAN = ("198.18.0.2", 19122)
GUEST = ("10.203.0.2", 19123)


def marker(prefix, suffix):
    return pathlib.Path(prefix + "." + suffix)


def signal(prefix, suffix):
    marker(prefix, suffix).write_text("1", encoding="ascii")


def await_signal(prefix, suffix, seconds=20):
    end = time.monotonic() + seconds
    while not marker(prefix, suffix).exists():
        if time.monotonic() >= end:
            raise TimeoutError("missing marker: " + suffix)
        time.sleep(0.02)


def server(prefix):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(WAN)
        # The client must never send INIT before this socket is bound.
        signal(prefix, "bound")
        sock.settimeout(15)
        packet, addr = sock.recvfrom(64)
        if packet != b"INIT" or addr != GUEST:
            raise RuntimeError("unexpected UDP opening: " + repr((packet, addr)))
        sock.sendto(b"ACK", GUEST)
        signal(prefix, "server-ready")
        await_signal(prefix, "trigger")
        sock.sendto(b"BLOCK", GUEST)
        signal(prefix, "sent")
        await_signal(prefix, "resume")
        sock.sendto(b"RESTORE", GUEST)
        signal(prefix, "restored-sent")


def client(prefix):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(GUEST)
        sock.settimeout(8)
        sock.sendto(b"INIT", WAN)
        packet, sender = sock.recvfrom(64)
        if packet != b"ACK" or sender != WAN:
            raise RuntimeError("initial authorized UDP handshake failed")
        signal(prefix, "client-ready")
        await_signal(prefix, "trigger")
        sock.settimeout(3)
        try:
            packet, sender = sock.recvfrom(64)
        except socket.timeout:
            signal(prefix, "blocked")
        else:
            raise RuntimeError("inbound UDP reached guest without authority: " + repr((packet, sender)))
        await_signal(prefix, "resume")
        sock.settimeout(8)
        packet, sender = sock.recvfrom(64)
        if packet != b"RESTORE" or sender != WAN:
            raise RuntimeError("inbound UDP did not recover on the same socket")
        signal(prefix, "recovered")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["server", "client"])
    parser.add_argument("prefix")
    args = parser.parse_args()
    # Distinct tuples keep the two cases independent. Server readiness is
    # coordinated separately using the bound marker before client startup.
    global WAN, GUEST
    offset = 10 if args.prefix.endswith("expiry") else 0
    WAN = (WAN[0], WAN[1] + offset)
    GUEST = (GUEST[0], GUEST[1] + offset)
    if args.role == "server":
        server(args.prefix)
    else:
        client(args.prefix)


if __name__ == "__main__":
    main()
