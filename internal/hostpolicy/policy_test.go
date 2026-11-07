package hostpolicy

import (
	"errors"
	"strings"
	"testing"
)

func TestScopedRenderers(t *testing.T) {
	id := Identity{GuestMAC: "02:00:00:00:00:11", UplinkMAC: "02:00:00:00:00:22", ManagementMAC: "02:00:00:00:00:33"}
	nm, err := RenderGuestExclusion(id)
	if err != nil {
		t.Fatal(err)
	}
	if nm != "[keyfile]\nunmanaged-devices=type:ethernet;except:mac:02:00:00:00:00:22\n" {
		t.Fatalf("unexpected exclusion: %q", nm)
	}
	netplan, err := RenderUplinkNetplanDefinition(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(netplan, "macaddress: 02:00:00:00:00:22") || strings.Contains(netplan, "00:11") || strings.Contains(netplan, "00:33") {
		t.Fatalf("uplink selector is not isolated: %q", netplan)
	}
	service := RenderNftablesServiceOverride()
	if strings.Contains(service, "flush") || !strings.Contains(service, "ExecStop=\n") || !strings.Contains(service, "ExecReload=\n") || !strings.Contains(service, "ExecStart=/usr/bin/true") {
		t.Fatalf("unsafe nft lifecycle proposal: %q", service)
	}
}

func TestRejectAmbiguousRolesAndInvalidMAC(t *testing.T) {
	base := Identity{GuestMAC: "02:00:00:00:00:11", UplinkMAC: "02:00:00:00:00:22", ManagementMAC: "02:00:00:00:00:33"}
	tests := map[string]Identity{
		"same guest and uplink":     {GuestMAC: base.GuestMAC, UplinkMAC: base.GuestMAC, ManagementMAC: base.ManagementMAC},
		"same guest and management": {GuestMAC: base.GuestMAC, UplinkMAC: base.UplinkMAC, ManagementMAC: base.GuestMAC},
		"empty":                     {GuestMAC: "", UplinkMAC: base.UplinkMAC, ManagementMAC: base.ManagementMAC},
		"multicast":                 {GuestMAC: "01:00:5e:00:00:01", UplinkMAC: base.UplinkMAC, ManagementMAC: base.ManagementMAC},
		"all zero":                  {GuestMAC: "00:00:00:00:00:00", UplinkMAC: base.UplinkMAC, ManagementMAC: base.ManagementMAC},
		"injection":                 {GuestMAC: "02:00:00:00:00:11\nmanaged=yes", UplinkMAC: base.UplinkMAC, ManagementMAC: base.ManagementMAC},
	}
	for label, id := range tests {
		t.Run(label, func(t *testing.T) {
			if _, err := RenderGuestExclusion(id); !errors.Is(err, ErrUnsafePlan) {
				t.Fatalf("exclusion accepted invalid identity: %v", err)
			}
			if _, err := RenderUplinkNetplanDefinition(id); !errors.Is(err, ErrUnsafePlan) {
				t.Fatalf("netplan accepted invalid identity: %v", err)
			}
		})
	}
}

func TestUSBDefaultDenyRequiresIndependentRecovery(t *testing.T) {
	all := USBBootEvidence{RootFilesystemNonUSB: true, ManagementPathNonUSB: true, RecoveryPathNonUSB: true, KernelParameterSupported: true}
	arg, err := RenderUSBDefaultDenyKernelArg(all)
	if err != nil || arg != "usbcore.authorized_default=0" {
		t.Fatalf("unexpected USB lockdown proposal: %q, %v", arg, err)
	}
	cases := []struct {
		name string
		breakCondition func(*USBBootEvidence)
	}{
		{"USB root storage", func(e *USBBootEvidence) { e.RootFilesystemNonUSB = false }},
		{"USB management", func(e *USBBootEvidence) { e.ManagementPathNonUSB = false }},
		{"USB recovery", func(e *USBBootEvidence) { e.RecoveryPathNonUSB = false }},
		{"unknown kernel support", func(e *USBBootEvidence) { e.KernelParameterSupported = false }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			bad := all
			tt.breakCondition(&bad)
			if arg, err := RenderUSBDefaultDenyKernelArg(bad); !errors.Is(err, ErrUnsafePlan) || arg != "" {
				t.Fatalf("unsafe USB lockdown accepted: %q, %v", arg, err)
			}
		})
	}
}

func TestProvisioningIsExplicitlyGated(t *testing.T) {
	for _, flags := range [][3]bool{{false, true, true}, {true, false, true}, {true, true, false}, {false, false, false}} {
		if err := EvaluateProvisioning(flags[0], flags[1], flags[2]); !errors.Is(err, ErrUnsafePlan) {
			t.Fatalf("accepted unsafe gate %v: %v", flags, err)
		}
	}
	if err := EvaluateProvisioning(true, true, true); err != nil {
		t.Fatal(err)
	}
}
