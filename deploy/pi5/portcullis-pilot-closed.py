#!/usr/bin/env python3
"""Supervised Pi 5 guard entry point. Keep the guest RJ45 disconnected."""
import errno
import json
import os
from pathlib import Path
import re
import subprocess
import sys

IFNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\Z")
IP = "/usr/sbin/ip"
POLICY = {"accept_ra": "0", "disable_ipv6": "1"}


def command(*argv):
    return subprocess.run(
        argv, check=True, capture_output=True, text=True, timeout=60,
        env={**os.environ, "LC_ALL": "C"},
    ).stdout.strip()


def read(path):
    return path.read_text(encoding="utf-8").strip()


def snapshot(config, pins, sysroot, run):
    guest = config["guest_interface"]
    if config["uplink_interface"] != "eth0" or not IFNAME.fullmatch(guest) or guest in {
        "all", "default", "eth0", "lo", "wlan0",
    }:
        raise ValueError("invalid physical roles")
    roles = [("guest", guest, "r8152"), ("uplink", "eth0", "macb"), ("management", "wlan0", "brcmfmac")]
    observed = []
    for role, name, driver in roles:
        link = sysroot / name
        device = (link / "device").resolve(strict=True)
        if str(device) != pins[role]["device"] or (device / "driver").resolve(strict=True).name != driver:
            raise ValueError("physical ancestry or driver changed")
        mac = read(link / "address")
        if mac != pins[role]["mac"] or int(read(link / "ifindex")) != pins[role]["ifindex"]:
            raise ValueError("interface identity changed")
        managed = run("/usr/bin/nmcli", "-t", "-f", "GENERAL.NM-MANAGED", "device", "show", name)
        expected = "no" if role == "guest" else "yes"
        if managed != "GENERAL.NM-MANAGED:" + expected:
            raise ValueError("NetworkManager ownership mismatch")
        observed.append(mac)
    if len(set(observed)) != len(roles):
        raise ValueError("overlapping MAC addresses")
    link = sysroot / guest
    usb = (link / "device").resolve(strict=True).parent
    if [read(usb / key) for key in ("idVendor", "idProduct")] != pins["guest"]["usb_id"]:
        raise ValueError("USB identity changed")
    permanent = run("/usr/sbin/ethtool", "-P", guest)
    if permanent != "Permanent address: " + pins["guest"]["mac"]:
        raise ValueError("guest permanent address changed")
    if (link / "master").exists() or any(link.glob("upper_*")):
        raise ValueError("guest is attached to another interface")
    return link


def check(config, pins, sysroot, run, *, allow_up=False):
    link = snapshot(config, pins, sysroot, run)
    up = bool(int(read(link / "flags"), 0) & 1)
    if up and not allow_up:
        raise ValueError("guest administratively UP")
    try:
        carrier = read(link / "carrier")
    except OSError as err:
        if up or err.errno != errno.EINVAL:
            raise
        # Linux cannot always read carrier on a DOWN link. The operator
        # verifies cable disconnection independently.
    else:
        if carrier != "0":
            raise ValueError("guest carrier not absent")
    routes = json.loads(run(IP, "-j", "-4", "route", "show", "default"))
    peer = json.loads(run(IP, "-j", "route", "get", pins["ssh_peer"]))
    if not routes or len(peer) != 1 or any(row.get("dev") != "wlan0" for row in routes + peer):
        raise ValueError("management route changed")
    if not allow_up:
        addresses = json.loads(run(IP, "-j", "address", "show", "dev", link.name))
        if len(addresses) != 1 or addresses[0].get("addr_info") != []:
            raise ValueError("guest has addresses")
        for family in ("-4", "-6"):
            if json.loads(run(IP, "-j", family, "route", "show", "table", "all", "dev", link.name)):
                raise ValueError("guest has routes")
    return link


def policy(target, desired, *, write):
    nodes = {key: target / key for key in desired}
    # Resolve and read both knobs before the first write.
    current = {key: read(node) for key, node in nodes.items()}
    if any(value not in {"0", "1"} for value in current.values()):
        raise ValueError("invalid IPv6 setting")
    if write:
        for key, node in nodes.items():
            if current[key] != desired[key]:
                node.write_text(desired[key] + "\n", encoding="utf-8")
    if any(read(nodes[key]) != value for key, value in desired.items()):
        raise ValueError("guest IPv6 readback failed")


def execute(mode, config_path, sysroot, procroot, boot_id, run=command):
    config = json.loads(read(config_path))
    pins = json.loads(read(config_path.with_name("pilot-pins.json")))
    # The boot ID lives outside sysfs. Read it before any link action.
    if read(boot_id) != pins["boot_id"]:
        raise ValueError("boot changed")
    if mode in {"install-guard", "attest"}:
        nft = run("/usr/bin/systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "nftables.service")
        if set(nft.splitlines()) != {"LoadState=masked", "ActiveState=inactive"}:
            raise ValueError("stock nftables lifecycle still available")
    link = check(config, pins, sysroot, run, allow_up=mode == "close")
    if mode == "close":
        run(IP, "link", "set", "dev", link.name, "down")
    if mode in {"install-guard", "attest", "restore-ipv6"}:
        desired = pins["guest"]["original_ipv6"] if mode == "restore-ipv6" else POLICY
        if set(desired) != set(POLICY) or any(value not in {"0", "1"} for value in desired.values()):
            raise ValueError("invalid saved IPv6 state")
        policy(procroot / link.name, desired, write=mode != "attest")
        check(config, pins, sysroot, run)
        if mode != "restore-ipv6":
            subcommand = "bootstrap-closed" if mode == "install-guard" else "attest-closed"
            run("/usr/local/bin/portcullisd", subcommand, "-config", str(config_path))
            policy(procroot / link.name, POLICY, write=False)
    check(config, pins, sysroot, run)


def main():
    modes = {"check", "close", "install-guard", "attest", "restore-ipv6"}
    if len(sys.argv) != 3 or sys.argv[1] not in modes:
        print("usage: portcullis-pilot-closed {check|close|install-guard|attest|restore-ipv6} CONFIG_JSON", file=sys.stderr)
        return 2
    try:
        execute(
            sys.argv[1], Path(sys.argv[2]), Path("/sys/class/net"),
            Path("/proc/sys/net/ipv6/conf"), Path("/proc/sys/kernel/random/boot_id"),
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as err:
        # Do not echo private link identifiers, config or command output.
        detail = type(err).__name__
        print("Portcullis closed-guest check failed: " + detail, file=sys.stderr)
        return 1
    print("Portcullis closed-guest check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
