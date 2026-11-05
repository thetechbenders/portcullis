package hostpreflight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func fixture() (Snapshot, Selection) {
	s := Snapshot{
		OS: "linux", Arch: "arm64", Kernel: "6.18.50+rpt-rpi-2712",
		IPv4Forwarding: boolPtr(false), IPv6Forwarding: boolPtr(false),
		Interfaces: []Interface{
			{Name: "eth0", Index: 2, MAC: "dc:a6:32:aa:bb:cc", Up: true, SysfsPath: "/sys/devices/platform/soc/eth0", Uppers: []string{}, Addresses: []string{"198.18.0.1/24"}},
			{Name: "usb0", Index: 4, MAC: "02:22:33:44:55:66", Up: false, SysfsPath: "/sys/devices/pci0000/usb0", Uppers: []string{}, Addresses: []string{}, IPv6Disabled: boolPtr(true), AcceptRA: intPtr(0), MACAssignType: intPtr(0)},
			{Name: "wlan0", Index: 3, MAC: "dc:a6:32:bb:cc:dd", Up: true, SysfsPath: "/sys/devices/platform/soc/wlan0", Uppers: []string{}, Addresses: []string{"192.168.1.119/24"}},
		},
		DefaultRoutes:  []Route{{Family: "ipv4", Interface: "eth0", Destination: "0.0.0.0/0", Default: true}},
		Routes:         []Route{{Family: "ipv4", Interface: "eth0", Destination: "0.0.0.0/0", Default: true}},
		InventoryError: []string{},
	}
	sel := Selection{Guest: "usb0", Uplink: "eth0", Management: "wlan0", PinnedGuestMAC: "02:22:33:44:55:66", PinnedGuestSysfs: "/sys/devices/pci0000/usb0", PinnedUplinkMAC: "dc:a6:32:aa:bb:cc", PinnedUplinkSysfs: "/sys/devices/platform/soc/eth0", PinnedManagementMAC: "dc:a6:32:bb:cc:dd", PinnedManagementSysfs: "/sys/devices/platform/soc/wlan0"}
	return s, sel
}

func codes(r Report) []string {
	out := []string{}
	for _, f := range r.Hazards {
		out = append(out, f.Code)
	}
	return out
}

func TestBaselineHasNoObservedHazardsButDoesNotAssessSafety(t *testing.T) {
	s, sel := fixture()
	r := Evaluate(s, sel)
	if len(r.Hazards) != 0 || len(r.NotAssessed) != 6 || r.SchemaVersion != SchemaVersion {
		t.Fatalf("clean observable fixture must retain unresolved safety gates: %+v", r)
	}
	if r.PlanSHA256 == "" {
		t.Fatal("missing plan digest")
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "deployment_authorized") || strings.Contains(string(b), "\"status\"") {
		t.Fatalf("inventory assessment must not grant or imply activation authority: %s", b)
	}
}

func TestPhysicalPreflightHazards(t *testing.T) {
	tests := []struct {
		name, blocker string
		modify        func(*Snapshot, *Selection)
	}{
		{"guest already up", "guest_exposed", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Up = true }},
		{"guest loopback", "guest_exposed", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Loopback = true }},
		{"guest with IPv4 address", "guest_has_addresses", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Addresses = []string{"10.10.10.2/24"} }},
		{"guest with IPv6 address", "guest_has_addresses", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Addresses = []string{"fe80::1/64"} }},
		{"guest enslaved", "guest_topology_conflict", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Master = "br0" }},
		{"guest upper VLAN", "guest_topology_conflict", func(s *Snapshot, _ *Selection) { s.Interfaces[1].Uppers = []string{"usb0.300"} }},
		{"uplink MAC mismatch", "uplink_mac_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedUplinkMAC = "00:00:00:00:00:01" }},
		{"uplink parent path mismatch", "uplink_path_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedUplinkSysfs = "/sys/devices/other" }},
		{"management MAC mismatch", "management_mac_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedManagementMAC = "00:00:00:00:00:01" }},
		{"management parent path mismatch", "management_path_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedManagementSysfs = "/sys/devices/other" }},
		{"guest MAC mismatch", "guest_mac_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedGuestMAC = "00:00:00:00:00:00" }},
		{"guest MAC missing", "guest_mac_unpinned", func(_ *Snapshot, sel *Selection) { sel.PinnedGuestMAC = "" }},
		{"guest sysfs identity mismatch", "guest_path_mismatch", func(_ *Snapshot, sel *Selection) { sel.PinnedGuestSysfs = "/not/the/device" }},
		{"guest sysfs identity missing", "guest_path_unpinned", func(_ *Snapshot, sel *Selection) { sel.PinnedGuestSysfs = "" }},
		{"IPv4 default through guest", "guest_route", func(s *Snapshot, _ *Selection) {
			s.Routes = []Route{{Family: "ipv4", Interface: "usb0", Destination: "0.0.0.0/0", Default: true}}
		}},
		{"IPv6 default through guest", "guest_route", func(s *Snapshot, _ *Selection) {
			s.Routes = []Route{{Family: "ipv6", Interface: "usb0", Destination: "::/0", Default: true}}
		}},
		{"management down", "management_inactive", func(s *Snapshot, _ *Selection) { s.Interfaces[2].Up = false }},
		{"management unaddressed", "management_inactive", func(s *Snapshot, _ *Selection) { s.Interfaces[2].Addresses = nil }},
		{"missing guest NIC", "interface_missing", func(s *Snapshot, _ *Selection) { s.Interfaces = s.Interfaces[:1] }},
		{"role collision", "overlapping_roles", func(_ *Snapshot, sel *Selection) { sel.Uplink = "wlan0" }},
		{"unselected interfaces", "interfaces_not_selected", func(_ *Snapshot, sel *Selection) { sel.Management = "" }},
		{"incomplete proc inventory", "inventory_incomplete", func(s *Snapshot, _ *Selection) { s.InventoryError = []string{"routes ipv6: permission denied"} }},
		{"non Pi arch", "unverified_target_arch", func(s *Snapshot, _ *Selection) { s.Arch = "amd64" }},
		{"IPv4 forwarding active", "ipv4_forwarding_active_or_unknown", func(s *Snapshot, _ *Selection) { s.IPv4Forwarding = boolPtr(true) }},
		{"IPv6 forwarding active", "ipv6_forwarding_active_or_unknown", func(s *Snapshot, _ *Selection) { s.IPv6Forwarding = boolPtr(true) }},
		{"guest IPv6 enabled", "guest_ipv6_enabled", func(s *Snapshot, _ *Selection) { s.Interfaces[1].IPv6Disabled = boolPtr(false) }},
		{"guest accepts RAs", "guest_accept_ra", func(s *Snapshot, _ *Selection) { s.Interfaces[1].AcceptRA = intPtr(1) }},
		{"guest MAC modified", "guest_mac_not_permanent", func(s *Snapshot, _ *Selection) { s.Interfaces[1].MACAssignType = intPtr(3) }},
		{"virtual guest NIC", "virtual_guest_interface", func(s *Snapshot, _ *Selection) { s.Interfaces[1].SysfsPath = "/sys/devices/virtual/net/usb0" }},
		{"uplink overlaps management", "management_uplink_overlap", func(s *Snapshot, _ *Selection) { s.Interfaces[0].Addresses = []string{"192.168.1.50/24"} }},
		{"unexpected active NIC", "unexpected_active_interface", func(s *Snapshot, _ *Selection) {
			s.Interfaces = append(s.Interfaces, Interface{Name: "eth9", Up: true})
		}},
		{"guest per-link IPv4 forwarding", "interface_ipv4_forwarding", func(s *Snapshot, _ *Selection) {
			s.Interfaces[1].IPv4Forwarding = boolPtr(true)
		}},
		{"uplink per-link IPv6 forwarding", "interface_ipv6_forwarding", func(s *Snapshot, _ *Selection) {
			s.Interfaces[0].IPv6Forwarding = boolPtr(true)
		}},
		{"IPv6 force forwarding", "interface_ipv6_force_forwarding", func(s *Snapshot, _ *Selection) {
			s.Interfaces[2].IPv6ForceForwarding = boolPtr(true)
		}},
		{"guest has non-default route", "guest_route", func(s *Snapshot, _ *Selection) {
			s.Routes = []Route{{Family: "ipv4", Interface: "usb0", Destination: "10.0.0.0/8"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, sel := fixture()
			tc.modify(&s, &sel)
			r := Evaluate(s, sel)
			if !slices.Contains(codes(r), tc.blocker) {
				t.Fatalf("expected %q in %v", tc.blocker, codes(r))
			}
			if len(r.Hazards) == 0 {
				t.Fatal("hazardous topology must produce a specific finding")
			}
		})
	}
}

func TestEmptySnapshotNeverBecomesSafe(t *testing.T) {
	r := Evaluate(Snapshot{}, Selection{})
	if !slices.Contains(codes(r), "interfaces_not_selected") ||
		!slices.Contains(codes(r), "unsupported_os") {
		t.Fatalf("empty input unsafe: %+v", r)
	}
}

func TestBoundedProcReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte("hello\nworld\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := readBoundedLines(path, 20)
	if err != nil || !slices.Equal(lines, []string{"hello", "world"}) {
		t.Fatalf("got %v err %v", lines, err)
	}
	if _, err := readBoundedLines(path, 5); err == nil {
		t.Fatal("oversized proc result must fail closed")
	}
	if _, err := readBoundedLines(filepath.Join(t.TempDir(), "missing"), 20); err == nil {
		t.Fatal("missing proc result must report an error")
	}
}

func TestCollectorSmokeOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only procfs/sysfs inventory")
	}
	s := Collect()
	if s.OS != "linux" || len(s.Interfaces) == 0 {
		t.Fatalf("collector omitted essential host facts: %+v", s)
	}
	loopback := false
	for _, nic := range s.Interfaces {
		if nic.Loopback {
			loopback = true
			break
		}
	}
	if !loopback {
		t.Fatalf("collector did not report a loopback interface: %+v", s.Interfaces)
	}
	r := Evaluate(s, Selection{})
	if !slices.Contains(codes(r), "interfaces_not_selected") {
		t.Fatal("an unselected real Linux host must report missing topology")
	}
}

func TestPilotLinkLocalAndManagementDefaultAreNotHazards(t *testing.T) {
	s, sel := fixture()
	s.Interfaces[0].Addresses = append(s.Interfaces[0].Addresses, "fe80::2/64", "169.254.8.1/16")
	s.Interfaces[2].Addresses = append(s.Interfaces[2].Addresses, "fe80::1/64", "169.254.9.1/16")
	s.Routes = []Route{{Family: "ipv4", Interface: "wlan0", Destination: "0.0.0.0/0", Default: true}}
	if got := codes(Evaluate(s, sel)); len(got) != 0 {
		t.Fatalf("isolated-uplink pilot should have no observed hazards, got %v", got)
	}
}

func TestGloballyUnavailableIPv6IsNotAFalseAlarm(t *testing.T) {
	s, sel := fixture()
	s.IPv6Unavailable = true
	s.IPv6Forwarding = nil
	s.Interfaces[1].IPv6Disabled = nil
	s.Interfaces[1].AcceptRA = nil
	if got := codes(Evaluate(s, sel)); len(got) != 0 {
		t.Fatalf("disabled IPv6 should not cause hazards: %v", got)
	}
}
func TestRedactedReportKeepsPseudonymousBootCorrelation(t *testing.T) {
	s, sel := fixture()
	s.BootID = "private-boot-id"
	a := RedactReport(Evaluate(s, sel))
	b := RedactReport(Evaluate(s, sel))
	if a.BootID == "" || a.BootID != b.BootID || a.BootID == s.BootID {
		t.Fatalf("bad boot correlation: %q", a.BootID)
	}
}

func TestMissingIPv6RouteProcfsOnlyAllowedWhenIPv6Unavailable(t *testing.T) {
	missing := os.ErrNotExist
	denied := os.ErrPermission
	cases := []struct {
		name, family string
		unavailable  bool
		err          error
		want         bool
	}{
		{"disabled IPv6 and missing route", "ipv6", true, missing, true},
		{"enabled IPv6 and missing route", "ipv6", false, missing, false},
		{"disabled IPv6 but permission denied", "ipv6", true, denied, false},
		{"IPv4 missing route", "ipv4", true, missing, false},
		{"disabled IPv6 but malformed route", "ipv6", true, os.ErrInvalid, false},
		{"disabled IPv6 and no error", "ipv6", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldIgnoreMissingIPv6Routes(tc.family, tc.unavailable, tc.err); got != tc.want {
				t.Fatalf("ignore=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestDefaultForwardingHazards(t *testing.T) {
	tests := []struct {
		name string
		ipv4, ipv6 bool
		unavailable bool
		want string
	}{
		{"IPv4 inherited forwarding", true, false, false, "ipv4_default_forwarding_enabled"},
		{"IPv6 inherited forwarding", false, true, false, "ipv6_default_forwarding_enabled"},
		{"IPv6 unavailable ignores stale default", false, true, true, ""},
		{"defaults disabled", false, false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, sel := fixture()
			s.IPv4DefaultForwarding = boolPtr(tc.ipv4)
			s.IPv6DefaultForwarding = boolPtr(tc.ipv6)
			s.IPv6Unavailable = tc.unavailable
			got := codes(Evaluate(s, sel))
			if tc.want == "" {
				if slices.Contains(got, "ipv4_default_forwarding_enabled") || slices.Contains(got, "ipv6_default_forwarding_enabled") {
					t.Fatalf("unexpected inherited forwarding hazard: %v", got)
				}
			} else if !slices.Contains(got, tc.want) {
				t.Fatalf("expected %s in %v", tc.want, got)
			}
		})
	}
}
