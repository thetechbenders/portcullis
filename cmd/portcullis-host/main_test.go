package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
			{Name: "eth0", Up: true, MAC: "dc:a6:32:aa:bb:cc", SysfsPath: "/sys/devices/platform/soc/eth0", Addresses: []string{"198.18.0.1/24"}},
			{Name: "wlan0", Up: true, MAC: "dc:a6:32:bb:cc:dd", SysfsPath: "/sys/devices/platform/soc/wlan0", Addresses: []string{"192.168.1.119/24"}},
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

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed output") }

func TestOutputFailureHasDistinctExitCode(t *testing.T) {
	var diag bytes.Buffer
	if code := run([]string{"inventory"}, failingWriter{}, &diag, testSnapshot); code != 3 {
		t.Fatalf("output failure must return 3, got %d", code)
	}
}
func TestMACEncodedInterfaceNamesRedacted(t *testing.T) {
	snap := testSnapshot()
	snap.Interfaces = append(snap.Interfaces, hostpreflight.Interface{Name: "enx001122aabbcc", Up: true})
	snap.Routes = append(snap.Routes, hostpreflight.Route{Family: "ipv4", Interface: "enx001122aabbcc", Destination: "10.0.0.0/8"})
	var out, diag bytes.Buffer
	if code := run([]string{"inventory"}, &out, &diag, func() hostpreflight.Snapshot { return snap }); code != 0 {
		t.Fatalf("inventory failed: %d %s", code, diag.String())
	}
	if strings.Contains(out.String(), "001122aabbcc") {
		t.Fatalf("MAC leaked through interface name: %s", out.String())
	}
}

func TestInventoryRedactsMACNamesInErrorsAndRoutes(t *testing.T) {
	snap := testSnapshot()
	for _, name := range []string{"enx001122aabbcc", "wlx00e04c6a1b2c", "wwx112233445566"} {
		snap.Interfaces = append(snap.Interfaces, hostpreflight.Interface{Name: name, Master: name, Uppers: []string{name}})
		snap.Routes = append(snap.Routes, hostpreflight.Route{Family: "ipv4", Interface: name, Destination: "10.0.0.0/8"})
		snap.InventoryError = append(snap.InventoryError, "cannot read /proc/sys/net/ipv4/conf/"+name+"/forwarding")
	}
	var out, diag bytes.Buffer
	if code := run([]string{"inventory"}, &out, &diag, func() hostpreflight.Snapshot { return snap }); code != 1 {
		t.Fatalf("inventory with read errors must return 1, got: %d %s", code, diag.String())
	}
	for _, secret := range []string{"001122aabbcc", "00e04c6a1b2c", "112233445566", "enx-redacted-", "/proc/sys/net/ipv4/conf/"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("redacted inventory leaked %q: %s", secret, out.String())
		}
	}
	if !strings.Contains(out.String(), "mac-interface-1") || !strings.Contains(out.String(), "mac-interface-2") {
		t.Fatalf("missing report-local aliases: %s", out.String())
	}
}
