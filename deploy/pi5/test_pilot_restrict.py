import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("portcullis-pilot-restrict.py")
spec = importlib.util.spec_from_file_location("pilot_restrict", MODULE)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotRestrictTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sysroot = self.root / "net"
        self.guest = self.sysroot / "guest0"
        self.guest.mkdir(parents=True)
        (self.guest / "device").mkdir()
        (self.guest / "flags").write_text("0x1002\n")
        self.procroot = self.root / "ipv6"
        self.policy = self.procroot / "guest0"
        self.policy.mkdir(parents=True)
        (self.policy / "disable_ipv6").write_text("0\n")
        (self.policy / "accept_ra").write_text("1\n")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"guest_interface": "guest0"}))

    def restrict(self):
        return pilot.restrict_guest(self.config, self.sysroot, self.procroot)

    def test_guest_only_policy(self):
        self.assertTrue(self.restrict())
        self.assertEqual((self.policy / "disable_ipv6").read_text().strip(), "1")
        self.assertEqual((self.policy / "accept_ra").read_text().strip(), "0")

    def test_guest_up_refused_without_writes(self):
        (self.guest / "flags").write_text("0x1003\n")
        with self.assertRaisesRegex(ValueError, "DOWN"):
            self.restrict()
        self.assertEqual((self.policy / "disable_ipv6").read_text().strip(), "0")

    def test_management_role_refused(self):
        self.config.write_text(json.dumps({"guest_interface": "wlan0"}))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.restrict()

    def test_invalid_path_refused(self):
        self.config.write_text(json.dumps({"guest_interface": "../wlan0"}))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.restrict()

    def test_missing_policy_refused(self):
        (self.policy / "accept_ra").unlink()
        with self.assertRaises(OSError):
            self.restrict()

    def test_missing_physical_parent_refused(self):
        (self.guest / "device").rmdir()
        with self.assertRaisesRegex(ValueError, "identity"):
            self.restrict()


if __name__ == "__main__":
    unittest.main()
