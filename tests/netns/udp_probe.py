#!/usr/bin/env python3
"""One-way UDP reachability probe, for disposable test namespaces only."""
import argparse
import pathlib
import socket
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["listen", "send"])
    p.add_argument("address")
    p.add_argument("--ready")
    a = p.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if a.mode == "send":
            sock.sendto(b"PORTCULLIS-UDP", (a.address, 19091))
        else:
            sock.bind((a.address, 19091))
            sock.settimeout(2)
            pathlib.Path(a.ready).write_text("ready", encoding="ascii")
            try:
                payload, _ = sock.recvfrom(128)
            except socket.timeout:
                sys.exit(1)
            if payload != b"PORTCULLIS-UDP":
                sys.exit(2)


if __name__ == "__main__":
    main()
