package hostpreflight

import (
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
    "pinned_guest_sysfs":"/sys/devices/pci0000/usb0"
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
	if Evaluate(s, sel).DeploymentAuthorized {
		t.Fatal("valid plan must not imply authorization")
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
		{"missing selection", "{\"schema_version\":1}"},
		{"role collision", strings.Replace(validHostPlan, "\"uplink\":\"eth0\"", "\"uplink\":\"usb0\"", 1)},
		{"bad interface name", strings.Replace(validHostPlan, "\"guest\":\"usb0\"", "\"guest\":\"../usb0\"", 1)},
		{"multicast MAC", strings.Replace(validHostPlan, "\"02:22:33:44:55:66\"", "\"01:22:33:44:55:66\"", 1)},
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
