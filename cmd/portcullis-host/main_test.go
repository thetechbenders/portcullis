package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
)

func testSnapshot() hostpreflight.Snapshot {
	disabled, enabled, zero := true, false, 0
	return hostpreflight.Snapshot{
		OS: "linux", Arch: "arm64", BootID: "test-boot", Hostname: "internal-host",
		IPv4Forwarding: &enabled, IPv6Forwarding: &enabled,
		Interfaces: []hostpreflight.Interface{
			{Name: "usb0", MAC: "02:22:33:44:55:66", SysfsPath: "/sys/devices/pci0000/usb0",
				IPv6Disabled: &disabled, AcceptRA: &zero, MACAssignType: &zero},
			{Name: "eth0", Up: true, Addresses: []string{"198.18.0.1/24"}},
			{Name: "wlan0", Up: true, Addresses: []string{"192.168.1.119/24"}},
		},
		Routes: []hostpreflight.Route{{Family: "ipv4", Interface: "eth0", Destination: "0.0.0.0/0", Default: true}},
	}
}

func TestInventoryDoesNotCreateAuthorityOrLeakPrivateIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		args        []string
		wantPrivate bool
	}{
		{[]string{"inventory"}, false},
		{[]string{"inventory", "-private"}, true},
	} {
		var out, diag bytes.Buffer
		if status := run(tc.args, &out, &diag, testSnapshot); status != 0 {
			t.Fatalf("inventory status %d: %s", status, diag.String())
		}
		var snap hostpreflight.Snapshot
		if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		if tc.wantPrivate {
			if snap.Hostname != "internal-host" || snap.Interfaces[0].MAC == "" {
				t.Fatal("explicitly private inventory omitted identifiers")
			}
		} else if strings.Contains(out.String(), "internal-host") || strings.Contains(out.String(), "02:22:33") ||
			strings.Contains(out.String(), "192.168.1.") || strings.Contains(out.String(), "/sys/devices/pci0000") {
			t.Fatalf("default inventory disclosed identifiers: %s", out.String())
		}
		if strings.Contains(out.String(), "deployment_authorized") {
			t.Fatal("inventory must not imply deployment authority")
		}
	}
}

func TestCheckExitCodesAndMissingPlan(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	body := `{"schema_version":1,"selection":{"guest":"usb0","uplink":"eth0","management":"wlan0","pinned_guest_mac":"02:22:33:44:55:66","pinned_guest_sysfs":"/sys/devices/pci0000/usb0","pinned_uplink_mac":"dc:a6:32:aa:bb:cc","pinned_uplink_sysfs":"/sys/devices/platform/soc/eth0","pinned_management_mac":"dc:a6:32:bb:cc:dd","pinned_management_sysfs":"/sys/devices/platform/soc/wlan0"}}`
	if err := os.WriteFile(plan, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if code := run([]string{"check", "-plan", plan}, &out, &diag, testSnapshot); code != 0 {
		t.Fatalf("expected zero observed hazards, got %d %s %s", code, out.String(), diag.String())
	}
	var checked hostpreflight.Report
	if err := json.Unmarshal(out.Bytes(), &checked); err != nil {
		t.Fatal(err)
	}
	if len(checked.NotAssessed) == 0 || len(checked.Hazards) != 0 || checked.PlanSHA256 == "" {
		t.Fatalf("zero observed hazards must still disclose unassessed checks: %+v", checked)
	}
	if strings.Contains(out.String(), "02:22:33:44:55:66") {
		t.Fatal("check leaked pinned MAC by default")
	}
	hazard := testSnapshot()
	hazard.Interfaces[0].Up = true
	out.Reset()
	diag.Reset()
	if code := run([]string{"check", "-plan", plan}, &out, &diag, func() hostpreflight.Snapshot { return hazard }); code != 1 {
		t.Fatalf("hazardous check must return 1, got %d", code)
	}
	for _, args := range [][]string{
		{"check"}, {"inventory", "-plan", plan}, {"inventory", "-dry-run=false"},
		{"check", "-plan", plan, "extra"}, {"preflight"}, {"inventory", "-nonsense"},
	} {
		out.Reset()
		diag.Reset()
		if code := run(args, &out, &diag, testSnapshot); code != 2 {
			t.Fatalf("invalid args %v got %d", args, code)
		}
	}
}
