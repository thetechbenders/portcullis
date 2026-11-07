import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

MODULE = Path(__file__).with_name("portcullis-pilot-closed.py")
spec = importlib.util.spec_from_file_location("pilot_closed", MODULE)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotClosedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sysroot = self.root / "net"
        self.guest = self.sysroot / "guest0"
        self.guest.mkdir(parents=True)
        (self.guest / "device").mkdir()
        (self.guest / "flags").write_text("0x1002\n")
        (self.guest / "carrier").write_text("0\n")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({
            "guest_interface": "guest0",
            "uplink_interface": "eth0",
        }))
        self.nm = "GENERAL.NM-MANAGED:no\n"
        self.routes = [{"dst": "default", "dev": "wlan0"}]

    def run_fake(self, args, **kwargs):
        if args[0].endswith("nmcli"):
            return SimpleNamespace(stdout=self.nm)
        if args[0].endswith("/ip"):
            return SimpleNamespace(stdout=json.dumps(self.routes))
        raise AssertionError("unexpected command")

    def check(self):
        return pilot.closed(self.config, self.sysroot, self.run_fake)

    def test_closed_eligible_snapshot(self):
        self.assertTrue(self.check())

    def test_up_refused(self):
        (self.guest / "flags").write_text("0x1003\n")
        with self.assertRaisesRegex(ValueError, "administratively UP"):
            self.check()

    def test_carrier_refused(self):
        (self.guest / "carrier").write_text("1\n")
        with self.assertRaisesRegex(ValueError, "carrier"):
            self.check()

    def test_managed_refused(self):
        self.nm = "GENERAL.NM-MANAGED:yes\n"
        with self.assertRaisesRegex(ValueError, "NetworkManager"):
            self.check()

    def test_wrong_management_route_refused(self):
        self.routes = [{"dst": "default", "dev": "eth0"}]
        with self.assertRaisesRegex(ValueError, "management"):
            self.check()

    def test_missing_management_route_refused(self):
        self.routes = []
        with self.assertRaisesRegex(ValueError, "management"):
            self.check()

    def test_overlapping_role_refused(self):
        self.config.write_text(json.dumps({
            "guest_interface": "wlan0",
            "uplink_interface": "eth0",
        }))
        with self.assertRaisesRegex(ValueError, "roles"):
            self.check()

    def test_missing_device_parent_refused(self):
        (self.guest / "device").rmdir()
        with self.assertRaisesRegex(ValueError, "physical"):
            self.check()

    def test_bad_interface_name_refused(self):
        self.config.write_text(json.dumps({
            "guest_interface": "../wlan0",
            "uplink_interface": "eth0",
        }))
        with self.assertRaisesRegex(ValueError, "guest"):
            self.check()


if __name__ == "__main__":
    unittest.main()
