import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).with_name("portcullis-pilot-closed.py")
spec = importlib.util.spec_from_file_location("pilot_closed", MODULE)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotClosedTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        self.sysroot = root / "net"
        self.procroot = root / "ipv6"
        self.boot_id = root / "boot_id"
        self.boot_id.write_text("current-boot")
        self.guest = self.sysroot / "guest0"
        self.target = self.procroot / "guest0"
        self.target.mkdir(parents=True)
        self.original = {"accept_ra": "1", "disable_ipv6": "0"}
        for key, value in self.original.items():
            (self.target / key).write_text(value + "\n")
        self.config = root / "config.json"
        self.config.write_text(json.dumps({"guest_interface": "guest0", "uplink_interface": "eth0"}))
        pins = {"boot_id": "current-boot", "ssh_peer": "192.0.2.3"}
        for index, (role, name, driver) in enumerate(
            [("guest", "guest0", "r8152"), ("uplink", "eth0", "macb"), ("management", "wlan0", "brcmfmac")],
            start=2,
        ):
            link = self.sysroot / name
            link.mkdir(parents=True)
            device = root / "devices" / name / "port"
            (device / "driver").mkdir(parents=True)
            driver_path = root / driver
            driver_path.mkdir()
            (device / "driver").rmdir()
            (device / "driver").symlink_to(driver_path)
            (link / "device").symlink_to(device)
            mac = f"02:00:00:00:00:{index:02x}"
            (link / "address").write_text(mac)
            (link / "ifindex").write_text(str(index))
            pins[role] = {"mac": mac, "ifindex": index, "device": str(device)}
        self.pins = self.config.with_name("pilot-pins.json")
        pins["guest"].update(usb_id=["0bda", "8156"], original_ipv6=self.original)
        self.pins.write_text(json.dumps(pins))
        (root / "devices/guest0/idVendor").write_text("0bda")
        (root / "devices/guest0/idProduct").write_text("8156")
        (self.guest / "flags").write_text("0x1002\n")
        (self.guest / "carrier").write_text("0\n")
        self.managed = {"guest0": "no", "eth0": "yes", "wlan0": "yes"}
        self.default = self.peer = "wlan0"
        self.nft = "LoadState=masked\nActiveState=inactive"
        self.failure = None
        self.after_daemon = lambda: None
        self.daemon = []

    def run_fake(self, *args):
        tool = Path(args[0]).name
        if tool == "nmcli":
            return "GENERAL.NM-MANAGED:" + self.managed[args[-1]]
        if tool == "ethtool":
            return "Permanent address: 02:00:00:00:00:02"
        if tool == "systemctl":
            return self.nft
        if tool == "portcullisd":
            self.daemon.append(args[1])
            self.after_daemon()
            if self.failure:
                raise subprocess.CalledProcessError(1, args)
            return ""
        if args[-1] == "default":
            return json.dumps([{"dev": self.default}])
        if "get" in args:
            return json.dumps([{"dev": self.peer}])
        if "address" in args:
            return '[{"addr_info":[]}]'
        if "route" in args:
            return "[]"
        if args[-1] == "down":
            (self.guest / "flags").write_text("0x1002\n")
            return ""
        raise AssertionError("unexpected command")

    def execute(self, mode="install-guard"):
        return pilot.execute(mode, self.config, self.sysroot, self.procroot, self.boot_id, self.run_fake)

    def values(self):
        return {key: (self.target / key).read_text().strip() for key in self.original}

    def test_bootstrap_and_readback_and_restore(self):
        self.execute()
        self.assertEqual(self.values(), pilot.POLICY)
        self.execute("attest")
        self.assertEqual(self.daemon, ["bootstrap-closed", "attest-closed"])
        self.execute("restore-ipv6")
        self.assertEqual(self.values(), self.original)

    def test_initial_close_requires_unmanaged_and_no_carrier(self):
        (self.guest / "flags").write_text("0x1003\n")
        self.managed["guest0"] = "yes"
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.execute("close")
        self.managed["guest0"] = "no"
        self.execute("close")
        self.assertEqual((self.guest / "flags").read_text(), "0x1002\n")
        self.assertEqual(self.values(), self.original)

    def test_unexpected_up_never_bootstraps(self):
        (self.guest / "flags").write_text("0x1003\n")
        with self.assertRaisesRegex(ValueError, "administratively UP"):
            self.execute()
        self.assertEqual(self.values(), self.original)
        self.assertEqual(self.daemon, [])

    def test_wrong_owner_or_route_refuses_before_writes(self):
        for attr, value in (("default", "eth0"), ("peer", "eth0"), ("nft", "LoadState=loaded\nActiveState=inactive")):
            with self.subTest(attr=attr):
                original = getattr(self, attr)
                setattr(self, attr, value)
                with self.assertRaises(ValueError):
                    self.execute()
                setattr(self, attr, original)
        self.assertEqual(self.values(), self.original)
        self.assertEqual(self.daemon, [])

    def test_missing_uplink_refuses_before_writes(self):
        (self.sysroot / "eth0/device").unlink()
        with self.assertRaises(FileNotFoundError):
            self.execute()
        self.assertEqual(self.values(), self.original)

    def test_identity_or_boot_drift_refuses_before_writes(self):
        for path, value in ((self.guest / "ifindex", "99"), (self.guest / "address", "02:00:00:00:00:99"),
                            (self.boot_id, "new-boot")):
            with self.subTest(file=path.name):
                original = path.read_text()
                path.write_text(value)
                with self.assertRaises(ValueError):
                    self.execute()
                path.write_text(original)
        self.assertEqual(self.values(), self.original)

    def test_drift_after_daemon_is_a_failed_start(self):
        self.after_daemon = lambda: (self.guest / "flags").write_text("0x1003")
        with self.assertRaisesRegex(ValueError, "administratively UP"):
            self.execute()

    def test_failed_bootstrap_retains_restrictions_and_retry_is_explicit(self):
        self.failure = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute()
        self.assertEqual(self.values(), pilot.POLICY)
        self.failure = False
        self.execute()
        self.assertEqual(self.daemon, ["bootstrap-closed", "bootstrap-closed"])

    def test_absent_ipv6_knob_prevents_partial_change(self):
        (self.target / "disable_ipv6").unlink()
        with self.assertRaises(FileNotFoundError):
            self.execute()
        self.assertEqual((self.target / "accept_ra").read_text().strip(), "1")
        self.assertEqual(self.daemon, [])


if __name__ == "__main__":
    unittest.main()
