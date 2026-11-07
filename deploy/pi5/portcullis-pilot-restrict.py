#!/usr/bin/env python3
"""Apply guest-only IPv6 policy for a cable-disconnected supervised pilot.

Requires privileged execution and a successful read-only closed-guest
preflight immediately beforehand. Does not raise an interface or touch
management/uplink/global sysctls. Never install as a hotplug auto-authorizer.
"""
import json
import pathlib
import re
import sys

IFNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\Z")


def restrict_guest(config_path, sysroot=pathlib.Path("/sys/class/net"), procroot=pathlib.Path("/proc/sys/net/ipv6/conf")):
    with open(config_path, encoding="utf-8") as file:
        config = json.load(file)
    guest = config.get("guest_interface")
    if not isinstance(guest, str) or not IFNAME.fullmatch(guest) or guest in ("wlan0", "eth0", "lo"):
        raise ValueError("guest role unsafe")
    physical = sysroot / guest
    if not (physical / "device").exists():
        raise ValueError("guest device identity unavailable")
    if int((physical / "flags").read_text().strip(), 0) & 1:
        raise ValueError("guest must already be administratively DOWN")
    target = procroot / guest
    if not target.is_dir():
        raise ValueError("guest IPv6 policy unavailable")
    for key, desired in (("accept_ra", "0"), ("disable_ipv6", "1")):
        node = target / key
        if not node.is_file():
            raise ValueError("guest IPv6 sysctl missing")
        node.write_text(desired + "\n")
        if node.read_text().strip() != desired:
            raise ValueError("guest IPv6 policy readback failed")
    if int((physical / "flags").read_text().strip(), 0) & 1:
        raise ValueError("guest unexpectedly became UP")
    return True


def main():
    if len(sys.argv) != 2:
        print("usage: portcullis-pilot-restrict CONFIG_JSON", file=sys.stderr)
        return 2
    try:
        restrict_guest(sys.argv[1])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        print("Portcullis guest-only IPv6 restriction refused; guest must remain closed", file=sys.stderr)
        return 1
    print("guest-only IPv6 restrictions read back; no link activation performed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
