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
	"github.com/thetechbenders/portcullis/internal/owneraudit"
)

func sample() hostpreflight.Snapshot {
	yes, no, zero := true, false, 0
	return hostpreflight.Snapshot{
		BootID: "private-boot", OS: "linux", Arch: "arm64",
		IPv4Forwarding: &no, IPv6Forwarding: &no,
		Interfaces: []hostpreflight.Interface{
			{Name: "usb0", Index: 4, MAC: "02:22:33:44:55:66", SysfsPath: "/sys/devices/pci0000/usb0", IPv6Disabled: &yes, AcceptRA: &zero, MACAssignType: &zero},
			{Name: "eth0", Index: 2, Up: true, MAC: "dc:a6:32:aa:bb:cc", SysfsPath: "/sys/devices/platform/soc/eth0", Addresses: []string{"198.18.0.1/24"}},
			{Name: "wlan0", Index: 3, Up: true, MAC: "dc:a6:32:bb:cc:dd", SysfsPath: "/sys/devices/platform/soc/wlan0", Addresses: []string{"192.168.1.119/24"}},
		},
	}
}

func planFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-plan.json")
	data := `{"schema_version":1,"selection":{"guest":"usb0","uplink":"eth0","management":"wlan0","pinned_guest_mac":"02:22:33:44:55:66","pinned_guest_sysfs":"/sys/devices/pci0000/usb0","pinned_uplink_mac":"dc:a6:32:aa:bb:cc","pinned_uplink_sysfs":"/sys/devices/platform/soc/eth0","pinned_management_mac":"dc:a6:32:bb:cc:dd","pinned_management_sysfs":"/sys/devices/platform/soc/wlan0"}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuditReadOnlyAndRedacted(t *testing.T) {
	path := planFile(t)
	for _, tc := range []struct {
		name, nm string
		snap     func() hostpreflight.Snapshot
		err      error
		wantExit int
		wantCode string
	}{
		{"unmanaged is only a diagnostic", "GENERAL.NM-MANAGED:no\nGENERAL.AUTOCONNECT:no\nGENERAL.CONNECTION:--\n", sample, nil, 0, ""},
		{"manager can activate", "GENERAL.NM-MANAGED:yes\nGENERAL.AUTOCONNECT:yes\nGENERAL.CONNECTION:Private WiFi\n", sample, nil, 1, "guest_networkmanager_managed"},
		{"nmcli failed", "", sample, errors.New("profile password SECRET"), 1, "networkmanager_observation_unavailable"},
		{"invalid nmcli", "GENERAL.NM-MANAGED:unknown\n", sample, nil, 1, "networkmanager_observation_unavailable"},
		{"guest unexpectedly up", "GENERAL.NM-MANAGED:no\nGENERAL.AUTOCONNECT:no\nGENERAL.CONNECTION:--\n", func() hostpreflight.Snapshot { s := sample(); s.Interfaces[0].Up = true; return s }, nil, 1, "host_preflight_hazard"},
		{"guest name stolen by another physical NIC", "GENERAL.NM-MANAGED:no\nGENERAL.AUTOCONNECT:no\nGENERAL.CONNECTION:--\n", func() hostpreflight.Snapshot {
			s := sample()
			s.Interfaces[0].SysfsPath = "/sys/devices/pci0000/other"
			return s
		}, nil, 1, "host_preflight_hazard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diag bytes.Buffer
			queries := 0
			code := run([]string{"check", "-plan", path}, &out, &diag, tc.snap, func(name string) ([]byte, error) {
				queries++
				if name != "usb0" {
					t.Fatalf("wrong guest query: %q", name)
				}
				return []byte(tc.nm), tc.err
			})
			if code != tc.wantExit || queries != 1 {
				t.Fatalf("status=%d queries=%d output=%s diag=%s", code, queries, out.String(), diag.String())
			}
			var got owneraudit.Report
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.NotAssessed) == 0 {
				t.Fatal("missing hard-stop caveats")
			}
			if tc.wantCode != "" {
				found := false
				for _, f := range got.Hazards {
					if f.Code == tc.wantCode {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %q in %+v", tc.wantCode, got)
				}
			}
			for _, leaked := range []string{"Private WiFi", "SECRET", "02:22:33:44:55:66", "/sys/devices/pci0000", "private-boot", "192.168.1.119"} {
				if strings.Contains(out.String()+diag.String(), leaked) {
					t.Fatalf("private data leaked: %q", leaked)
				}
			}
		})
	}
}

func TestAuditArgumentAndPlanFailuresBeforeQuery(t *testing.T) {
	for _, args := range [][]string{{}, {"inventory"}, {"check"}, {"check", "-plan", "missing"}, {"check", "-plan", "foo", "extra"}, {"check", "-unknown"}} {
		var out, diag bytes.Buffer
		code := run(args, &out, &diag, func() hostpreflight.Snapshot {
			t.Fatal("collected without a valid plan")
			return hostpreflight.Snapshot{}
		}, func(string) ([]byte, error) { t.Fatal("queried manager without valid plan"); return nil, nil })
		if code != 2 {
			t.Fatalf("%v: code %d diag %s", args, code, diag.String())
		}
	}
}

func TestBoundedOutput(t *testing.T) {
	b := &limitedOutput{limit: 3}
	if n, err := b.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := b.Write([]byte("cd")); !errors.Is(err, owneraudit.ErrObservation) || !b.overflow {
		t.Fatal("accepted oversized command output")
	}
}
