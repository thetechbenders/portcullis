package hostpreflight

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixture() (Snapshot, Selection) {
	s := Snapshot{
		OS: "linux", Arch: "arm64", Kernel: "6.18.50+rpt-rpi-2712",
		Interfaces: []Interface{
			{Name: "eth0", Index: 2, MAC: "dc:a6:32:aa:bb:cc", Up: true, SysfsPath: "/sys/devices/platform/soc/eth0", Uppers: []string{}, Addresses: []string{"192.168.1.20/24"}},
			{Name: "usb0", Index: 4, MAC: "02:22:33:44:55:66", Up: false, SysfsPath: "/sys/devices/pci0000/usb0", Uppers: []string{}, Addresses: []string{}},
			{Name: "wlan0", Index: 3, MAC: "dc:a6:32:bb:cc:dd", Up: true, SysfsPath: "/sys/devices/platform/soc/wlan0", Uppers: []string{}, Addresses: []string{"192.168.1.119/24"}},
		},
		DefaultRoutes: []Route{{Family:"ipv4", Interface:"wlan0"}},
		InventoryError: []string{},
	}
	sel := Selection{Guest: "usb0", Uplink: "eth0", Management:"wlan0", PinnedGuestMAC:"02:22:33:44:55:66", PinnedGuestSysfs:"/sys/devices/pci0000/usb0"}
	return s, sel
}

func codes(r Report) []string {
	out := []string{}
	for _, f := range r.Findings { out = append(out, f.Code) }
	return out
}

func TestBaselineRemainsBlocked(t *testing.T) {
	s, sel := fixture()
	r := Evaluate(s, sel)
	if r.Status != "blocked" || r.DeploymentAuthorized || !r.ReadOnly || r.SchemaVersion != SchemaVersion {
		t.Fatalf("preflight must never authorize deployment: %+v", r)
	}
	expected := []string{"manager_ownership_unverified", "kernel_guard_unverified", "physical_gate_unverified", "recovery_unverified", "physical_acceptance_outstanding"}
	if got := codes(r); !slices.Equal(got, expected) {
		t.Fatalf("unexpected baseline blockers:\n got %v\nwant %v", got, expected)
	}
	if len(r.Snapshot.Interfaces) != 3 { t.Fatal("snapshot omitted interface inventory") }
	b, err := json.Marshal(r)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(b), "\"deployment_authorized\":false") {
		t.Fatalf("JSON did not carry explicit authorization=false: %s", b)
	}
}

func TestPhysicalPreflightHazards(t *testing.T) {
	tests := []struct{
		name, blocker string
		modify func(*Snapshot, *Selection)
	}{
		{"guest already up", "guest_exposed", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Up=true}},
		{"guest loopback", "guest_exposed", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Loopback=true}},
		{"guest with IPv4 address", "guest_has_addresses", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Addresses=[]string{"10.10.10.2/24"}}},
		{"guest with IPv6 address", "guest_has_addresses", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Addresses=[]string{"fe80::1/64"}}},
		{"guest enslaved", "guest_topology_conflict", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Master="br0"}},
		{"guest upper VLAN", "guest_topology_conflict", func(s *Snapshot, _ *Selection) {s.Interfaces[1].Uppers=[]string{"usb0.300"}}},
		{"guest MAC mismatch", "guest_mac_mismatch", func(_ *Snapshot, sel *Selection) {sel.PinnedGuestMAC="00:00:00:00:00:00"}},
		{"guest MAC missing", "guest_mac_unpinned", func(_ *Snapshot, sel *Selection) {sel.PinnedGuestMAC=""}},
		{"guest sysfs identity mismatch", "guest_path_mismatch", func(_ *Snapshot, sel *Selection) {sel.PinnedGuestSysfs="/not/the/device"}},
		{"guest sysfs identity missing", "guest_path_unpinned", func(_ *Snapshot, sel *Selection) {sel.PinnedGuestSysfs=""}},
		{"IPv4 default through guest", "guest_default_route", func(s *Snapshot, _ *Selection) {s.DefaultRoutes=[]Route{{Family:"ipv4",Interface:"usb0"}}}},
		{"IPv6 default through guest", "guest_default_route", func(s *Snapshot, _ *Selection) {s.DefaultRoutes=[]Route{{Family:"ipv6",Interface:"usb0"}}}},
		{"management down", "management_inactive", func(s *Snapshot, _ *Selection) {s.Interfaces[2].Up=false}},
		{"management unaddressed", "management_inactive", func(s *Snapshot, _ *Selection) {s.Interfaces[2].Addresses=nil}},
		{"missing guest NIC", "interface_missing", func(s *Snapshot, _ *Selection) {s.Interfaces=s.Interfaces[:1]}},
		{"role collision", "overlapping_roles", func(_ *Snapshot, sel *Selection) {sel.Uplink="wlan0"}},
		{"unselected interfaces", "interfaces_not_selected", func(_ *Snapshot, sel *Selection) {sel.Management=""}},
		{"incomplete proc inventory", "inventory_incomplete", func(s *Snapshot, _ *Selection) {s.InventoryError=[]string{"routes ipv6: permission denied"}}},
		{"non Pi arch", "unverified_target_arch", func(s *Snapshot, _ *Selection) {s.Arch="amd64"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, sel := fixture()
			tc.modify(&s, &sel)
			r := Evaluate(s, sel)
			if !slices.Contains(codes(r), tc.blocker) {
				t.Fatalf("expected %q in %v", tc.blocker, codes(r))
			}
			if r.DeploymentAuthorized || r.Status!="blocked" {
				t.Fatal("a hazardous topology must not authorize deployment")
			}
		})
	}
}

func TestEmptySnapshotNeverBecomesSafe(t *testing.T) {
	r := Evaluate(Snapshot{}, Selection{})
	if r.DeploymentAuthorized || r.Status != "blocked" ||
		!slices.Contains(codes(r), "interfaces_not_selected") ||
		!slices.Contains(codes(r), "unsupported_os") {
		t.Fatalf("empty input unsafe: %+v", r)
	}
}

func TestBoundedProcReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte("hello\nworld\n"), 0600); err != nil { t.Fatal(err) }
	lines, err := readBoundedLines(path, 20)
	if err != nil || !slices.Equal(lines, []string{"hello","world"}) {
		t.Fatalf("got %v err %v",lines,err)
	}
	if _, err := readBoundedLines(path, 5); err == nil {
		t.Fatal("oversized proc result must fail closed")
	}
	if _, err := readBoundedLines(filepath.Join(t.TempDir(), "missing"),20); err == nil {
		t.Fatal("missing proc result must report an error")
	}
}
