#!/usr/bin/env python3
"""Rehearse a single wired-source replacement and rollback in a temporary root."""
import argparse
import configparser
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def profiles(root):
    directory = root / "run/NetworkManager/system-connections"
    return {path.name: path.read_bytes() for path in directory.glob("netplan-*.nmconnection")}


def keyfile(data):
    profile = configparser.ConfigParser(interpolation=None)
    profile.read_string(data.decode("utf-8"))
    return profile


def generate(root):
    result = subprocess.run(
        ["/usr/sbin/netplan", "generate", "--root-dir", str(root)],
        capture_output=True, check=True, timeout=30,
    )
    if result.stderr:
        raise ValueError("netplan emitted diagnostics")
    return profiles(root)


def validate(baseline, replacement, uplink_mac):
    if not re.fullmatch(r"90-NM-[0-9a-f-]{36}\.yaml", replacement.name):
        raise ValueError("replacement must name the original wired YAML")
    with tempfile.TemporaryDirectory(prefix="pc-netplan-") as tmp:
        root = Path(tmp)
        for directory in ("etc/netplan", "lib/netplan", "run/netplan"):
            if (baseline / directory).is_dir():
                shutil.copytree(baseline / directory, root / directory)
        # The packaged global renderer file is public, which upstream
        # Netplan warns about even inside a private rehearsal directory.
        # Normalize permissions on its sandbox copy only.
        vendor = root / "lib/netplan/00-network-manager-all.yaml"
        if vendor.is_file():
            vendor.chmod(0o600)
        target = root / "etc/netplan" / replacement.name
        source = target.read_bytes()
        before = generate(root)
        wired = [name for name, data in before.items() if keyfile(data)["connection"]["type"] == "ethernet"]
        wifi = [name for name, data in before.items() if keyfile(data)["connection"]["type"] == "wifi"]
        if len(wired) != 1 or len(wifi) != 1 or len(before) != 2:
            raise ValueError("unexpected generated profile inventory")

        target.write_bytes(replacement.read_bytes())
        after = generate(root)
        if before.keys() != after.keys() or before[wifi[0]] != after[wifi[0]]:
            raise ValueError("management profile or inventory changed")
        nm_config = root / "run/NetworkManager/conf.d/netplan.conf"
        if nm_config.exists() and "match-device=type:ethernet" in nm_config.read_text():
            raise ValueError("Netplan still marks all Ethernet devices as managed")
        old, new = keyfile(before[wired[0]]), keyfile(after[wired[0]])
        if old["connection"]["uuid"] != new["connection"]["uuid"]:
            raise ValueError("wired profile UUID changed")
        if new["connection"].get("autoconnect") != "false":
            raise ValueError("wired autoconnect must be disabled for the closed pilot")
        if new["ethernet"].get("mac-address", "").lower() != uplink_mac.lower():
            raise ValueError("wired permanent MAC match missing")
        # Depending on the generator, a literal name can be in either section.
        if new["connection"].get("interface-name") != "eth0" and new.get("match", "interface-name", fallback="") != "eth0;":
            raise ValueError("wired interface name match missing")
        target.write_bytes(source)
        if generate(root) != before:
            raise ValueError("rollback failed to reproduce the baseline profiles")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("replacement", type=Path)
    parser.add_argument("pins", type=Path)
    args = parser.parse_args()
    try:
        uplink = json.loads(args.pins.read_text(encoding="utf-8"))["uplink"]["mac"]
        validate(args.baseline, args.replacement, uplink)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as err:
        detail = str(err) if type(err) is ValueError else type(err).__name__
        raise SystemExit("private Netplan rehearsal failed: " + detail) from None
    print("Netplan install and rollback generation passed")


if __name__ == "__main__":
    main()
