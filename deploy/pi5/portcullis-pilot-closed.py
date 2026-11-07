#!/usr/bin/env python3
"""Read-only first-Pi-pilot guard bootstrap gate. NEVER raises an interface.

This protects a supervised, physically disconnected first install only.
It is not a pre-packet or unattended connected-boot isolation mechanism.
"""
import json
import pathlib
import re
import subprocess
import sys

IFNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\Z")


def closed(config_path, sysroot=pathlib.Path("/sys/class/net"), run=subprocess.run):
    with open(config_path, encoding="utf-8") as file:
        config = json.load(file)
    guest = config.get("guest_interface")
    uplink = config.get("uplink_interface")
    if not isinstance(guest, str) or not IFNAME.fullmatch(guest):
        raise ValueError("invalid guest interface")
    if not isinstance(uplink, str) or not IFNAME.fullmatch(uplink) or guest in (uplink, "wlan0") or uplink == "wlan0":
        raise ValueError("invalid or overlapping physical roles")
    guest_dir = sysroot / guest
    if not (guest_dir / "device").exists():
        raise ValueError("guest does not have physical device ancestry")
    flags = int((guest_dir / "flags").read_text().strip(), 0)
    if flags & 1:
        raise ValueError("guest administratively UP")
    # Missing carrier evidence is unknown, not a safe zero.
    if (guest_dir / "carrier").read_text().strip() != "0":
        raise ValueError("guest carrier is present or unverified")
    nm = run(
        ["/usr/bin/nmcli", "-t", "-f", "GENERAL.NM-MANAGED", "device", "show", guest],
        capture_output=True, text=True, timeout=5, check=True,
    )
    if any(not row.endswith(":no") for row in nm.stdout.strip().splitlines()) or not nm.stdout.strip():
        raise ValueError("guest NetworkManager exclusion not confirmed")
    route = run(
        ["/usr/sbin/ip", "-j", "-4", "route", "show", "default"],
        capture_output=True, text=True, timeout=5, check=True,
    )
    routes = json.loads(route.stdout)
    if not isinstance(routes, list) or not routes or any(r.get("dev") != "wlan0" for r in routes):
        raise ValueError("management default route not exclusively on wlan0")
    return True


def main():
    if len(sys.argv) != 2:
        print("usage: portcullis-pilot-closed CONFIG_JSON", file=sys.stderr)
        return 2
    try:
        closed(sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as err:
        # Avoid printing private interface names, routes or file content.
        print("Portcullis first-pilot bootstrap gate refused: " + type(err).__name__, file=sys.stderr)
        return 1
    print("first-pilot closed-guest preflight passed (snapshot, not physical isolation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
