package hostpreflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHostPlan = `{
  "schema_version":1,
  "selection":{
    "guest":"usb0",
    "uplink":"eth0",
    "management":"wlan0",
    "pinned_guest_mac":"02:22:33:44:55:66",
    "pinned_guest_sysfs":"/sys/devices/pci0000/usb0",
    "pinned_uplink_mac":"dc:a6:32:aa:bb:cc",
    "pinned_uplink_sysfs":"/sys/devices/platform/soc/eth0",
    "pinned_management_mac":"dc:a6:32:bb:cc:dd",
    "pinned_management_sysfs":"/sys/devices/platform/soc/wlan0"
  }
}`

func TestParsePlanAcceptsPinnedIdentities(t *testing.T) {
	sel, err := ParsePlan([]byte(validHostPlan))
	if err != nil {
		t.Fatal(err)
	}
	if sel.Guest != "usb0" || sel.Uplink != "eth0" || sel.Management != "wlan0" ||
		sel.PinnedGuestMAC != "02:22:33:44:55:66" ||
		sel.PinnedGuestSysfs != "/sys/devices/pci0000/usb0" {
		t.Fatalf("unexpected selection: %+v", sel)
	}
	s, _ := fixture()
	if len(Evaluate(s, sel).Hazards) != 0 {
		t.Fatal("valid fixture must have no observed hazards, without implying deployment authority")
	}
}

func TestParsePlanRejectsAmbiguityAndBadPins(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"oversized", strings.Repeat(" ", maxPlanBytes+1)},
		{"empty", ""},
		{"trailing object", validHostPlan + "{}"},
		{"unknown key", strings.Replace(validHostPlan, "\"schema_version\":1,", "\"unexpected\":true,\"schema_version\":1,", 1)},
		{"wrong version", strings.Replace(validHostPlan, "\"schema_version\":1", "\"schema_version\":2", 1)},
		{"duplicate top-level key", strings.Replace(validHostPlan, "\"schema_version\":1,", "\"schema_version\":1,\"schema_version\":1,", 1)},
		{"duplicate nested key", strings.Replace(validHostPlan, "\"guest\":\"usb0\",", "\"guest\":\"usb0\",\"guest\":\"usb0\",", 1)},
		{"case-variant duplicate", strings.Replace(validHostPlan, "\"guest\":\"usb0\",", "\"guest\":\"usb0\",\"GUEST\":\"eth7\",", 1)},
		{"capitalized field", strings.Replace(validHostPlan, "\"selection\":{", "\"Selection\":{", 1)},
		{"virtual guest sysfs", strings.Replace(validHostPlan, "/sys/devices/pci0000/usb0", "/sys/devices/virtual/net/veth0", 1)},
		{"missing selection", "{\"schema_version\":1}"},
		{"role collision", strings.Replace(validHostPlan, "\"uplink\":\"eth0\"", "\"uplink\":\"usb0\"", 1)},
		{"bad interface name", strings.Replace(validHostPlan, "\"guest\":\"usb0\"", "\"guest\":\"../usb0\"", 1)},
		{"zero MAC", strings.Replace(validHostPlan, "02:22:33:44:55:66", "00:00:00:00:00:00", 1)},
		{"duplicate MAC pins", strings.Replace(validHostPlan, "dc:a6:32:aa:bb:cc", "02:22:33:44:55:66", 1)},
		{"duplicate physical path", strings.Replace(validHostPlan, "/sys/devices/platform/soc/eth0", "/sys/devices/pci0000/usb0", 1)},
		{"reserved interface name", strings.Replace(validHostPlan, "\"guest\":\"usb0\"", "\"guest\":\"all\"", 1)},
		{"loopback role", strings.Replace(validHostPlan, "\"guest\":\"usb0\"", "\"guest\":\"lo\"", 1)},
		{"multicast MAC", strings.Replace(validHostPlan, "\"02:22:33:44:55:66\"", "\"01:22:33:44:55:66\"", 1)},
		{"missing uplink pin", strings.Replace(validHostPlan, "\"pinned_uplink_mac\":\"dc:a6:32:aa:bb:cc\"", "\"pinned_uplink_mac\":\"\"", 1)},
		{"missing management pin", strings.Replace(validHostPlan, "\"pinned_management_sysfs\":\"/sys/devices/platform/soc/wlan0\"", "\"pinned_management_sysfs\":\"\"", 1)},
		{"missing MAC", strings.Replace(validHostPlan, "\"pinned_guest_mac\":\"02:22:33:44:55:66\"", "\"pinned_guest_mac\":\"\"", 1)},
		{"non sysfs path", strings.Replace(validHostPlan, "\"/sys/devices/pci0000/usb0\"", "\"/tmp/usb0\"", 1)},
		{"unclean sysfs path", strings.Replace(validHostPlan, "\"/sys/devices/pci0000/usb0\"", "\"/sys/devices/../usb0\"", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePlan([]byte(tc.data)); err == nil {
				t.Fatalf("accepted invalid host plan %q", tc.data)
			}
		})
	}
}

func TestPlanCanonicalMACAndSafeFileType(t *testing.T) {
	plan := strings.Replace(validHostPlan, "02:22:33:44:55:66", "02-22-33-44-55-66", 1)
	sel, err := ParsePlan([]byte(plan))
	if err != nil || sel.PinnedGuestMAC != "02:22:33:44:55:66" {
		t.Fatalf("MAC not normalized: %+v %v", sel, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, []byte(validHostPlan), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "plan-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(link); err == nil {
		t.Fatal("symlink plans must be rejected")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPlan(path); err == nil {
		t.Fatal("world-writable plans must be rejected")
	}
}
