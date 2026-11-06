package hostpreflight

import (
	"slices"
	"testing"
)

func TestContinuityFindings(t *testing.T) {
	base, _ := fixture()
	base.BootID = "boot-a"
	copySnapshot := func() Snapshot {
		n := base
		n.Interfaces = append([]Interface(nil), base.Interfaces...)
		return n
	}
	for _, tc := range []struct {
		name   string
		change func(*Snapshot)
		want   string
	}{
		{"unchanged", func(*Snapshot) {}, ""},
		{"missing boot id", func(s *Snapshot) { s.BootID = "" }, "boot_identity_changed"},
		{"different boot", func(s *Snapshot) { s.BootID = "boot-b" }, "boot_identity_changed"},
		{"guest ifindex reused", func(s *Snapshot) { s.Interfaces[1].Index = 12 }, "interface_index_changed"},
		{"rename", func(s *Snapshot) { s.Interfaces[1].Name = "renamed0" }, "interface_removed"},
		{"re-enumeration under new name", func(s *Snapshot) {
			s.Interfaces[1] = Interface{Name: "enx001122334455", Index: 14, MAC: s.Interfaces[1].MAC, SysfsPath: s.Interfaces[1].SysfsPath}
		}, "interface_added"},
		{"unexpected new inactive interface", func(s *Snapshot) {
			s.Interfaces = append(s.Interfaces, Interface{Name: "enx001122334455", Index: 50})
		}, "interface_added"},
		{"nic disappeared", func(s *Snapshot) { s.Interfaces = s.Interfaces[:2] }, "interface_removed"},
		{"same name new MAC", func(s *Snapshot) { s.Interfaces[1].MAC = "02:00:00:00:00:fe" }, "interface_physical_identity_changed"},
		{"same name new physical parent", func(s *Snapshot) { s.Interfaces[1].SysfsPath = "/sys/devices/pci0000/other" }, "interface_physical_identity_changed"},
		{"zero current ifindex", func(s *Snapshot) { s.Interfaces[1].Index = 0 }, "interface_identity_incomplete"},
		{"duplicated interface name", func(s *Snapshot) { s.Interfaces[1].Name = "eth0" }, "interface_identity_incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := copySnapshot()
			tc.change(&s)
			got := ContinuityFindings(base, s)
			codes := make([]string, 0, len(got))
			for _, h := range got {
				codes = append(codes, h.Code)
			}
			if tc.want == "" && len(got) != 0 {
				t.Fatalf("unchanged snapshot flagged: %v", codes)
			}
			if tc.want != "" && !slices.Contains(codes, tc.want) {
				t.Fatalf("want %q, got %v", tc.want, codes)
			}
		})
	}
}

func TestContinuityMissingBaselineIdentityFails(t *testing.T) {
	base, _ := fixture()
	base.BootID = "boot-a"
	base.Interfaces[1].Index = 0
	current := base
	current.Interfaces = append([]Interface(nil), base.Interfaces...)
	codes := []string{}
	for _, f := range ContinuityFindings(base, current) {
		codes = append(codes, f.Code)
	}
	if !slices.Contains(codes, "baseline_identity_incomplete") {
		t.Fatalf("missing fail-closed baseline error: %v", codes)
	}
}
