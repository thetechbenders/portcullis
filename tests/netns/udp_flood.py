#!/usr/bin/env python3
"""High-rate UDP stress probe for disposable namespace reconciliation tests."""
import argparse
import pathlib
import socket
import time


def path(prefix, extension):
    return pathlib.Path(prefix + "." + extension)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["send", "receive"])
    parser.add_argument("prefix")
    args = parser.parse_args()
    deadline = time.monotonic() + 25
    if args.role == "receive":
        count = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("198.18.0.2", 19180))
            sock.settimeout(0.1)
            path(args.prefix, "ready").touch()
            while not path(args.prefix, "stop").exists():
                if time.monotonic() > deadline:
                    raise TimeoutError("stress receiver timed out")
                try:
                    sock.recvfrom(64)
                    count += 1
                except socket.timeout:
                    pass
            # Drain any late packets already admitted before reporting.
            end = time.monotonic() + 0.25
            while time.monotonic() < end:
                try:
                    sock.recvfrom(64)
                    count += 1
                except socket.timeout:
                    continue
        path(args.prefix, "received").write_text(str(count), encoding="ascii")
    else:
        count = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("10.203.0.2", 0))
            while not path(args.prefix, "ready").exists():
                if time.monotonic() > deadline:
                    raise TimeoutError("stress sender missing receiver")
                time.sleep(0.01)
            while not path(args.prefix, "stop").exists():
                if time.monotonic() > deadline:
                    raise TimeoutError("stress sender timed out")
                sock.sendto(b"STRESS", ("198.18.0.2", 19180))
                count += 1
        path(args.prefix, "sent").write_text(str(count), encoding="ascii")


if __name__ == "__main__":
    main()
