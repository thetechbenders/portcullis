package hostpolicy

import (
	"errors"
	"testing"
)

func TestUSBAdmissionRejectsEveryMissingCondition(t *testing.T) {
	e := USBAdmissionEvidence{
		KernelDefaultDenyVerified: true, DeviceCurrentlyUnauthorized: true,
		PhysicalUSBIdentityVerified: true, GuestCableDisconnected: true,
		IndependentRecoveryVerified: true, ManagementRoutePreserved: true,
		UplinkOwnerVerified: true, StrictEthernetExclusionVerified: true,
		NoCompetingManager: true, GuardInstalledAndAttested: true,
		FirewallLifecycleSafe: true, BootID: "boot-A",
		DeviceGeneration: "usb-A", GuardDigest: "guard-A",
	}
	a := USBAdmissionApproval{Valid: true, BootID: e.BootID, DeviceGeneration: e.DeviceGeneration, GuardDigest: e.GuardDigest}
	if err := PermitUSBDeviceAuthorization(e, a); err != nil {
		t.Fatal(err)
	}
	testCases := map[string]func(*USBAdmissionEvidence){
		"kernel lockdown absent": func(x *USBAdmissionEvidence) { x.KernelDefaultDenyVerified = false },
		"device already authorized": func(x *USBAdmissionEvidence) { x.DeviceCurrentlyUnauthorized = false },
		"unverified hardware": func(x *USBAdmissionEvidence) { x.PhysicalUSBIdentityVerified = false },
		"cable connected": func(x *USBAdmissionEvidence) { x.GuestCableDisconnected = false },
		"no independent recovery": func(x *USBAdmissionEvidence) { x.IndependentRecoveryVerified = false },
		"management route changed": func(x *USBAdmissionEvidence) { x.ManagementRoutePreserved = false },
		"uplink swapped": func(x *USBAdmissionEvidence) { x.UplinkOwnerVerified = false },
		"manager exclusion missed": func(x *USBAdmissionEvidence) { x.StrictEthernetExclusionVerified = false },
		"competing manager": func(x *USBAdmissionEvidence) { x.NoCompetingManager = false },
		"guard absent": func(x *USBAdmissionEvidence) { x.GuardInstalledAndAttested = false },
		"nftables lifecycle unsafe": func(x *USBAdmissionEvidence) { x.FirewallLifecycleSafe = false },
		"boot unknown": func(x *USBAdmissionEvidence) { x.BootID = "" },
		"USB generation unknown": func(x *USBAdmissionEvidence) { x.DeviceGeneration = "" },
		"guard digest unknown": func(x *USBAdmissionEvidence) { x.GuardDigest = "" },
	}
	for name, mutate := range testCases {
		t.Run(name, func(t *testing.T) {
			bad := e
			mutate(&bad)
			if err := PermitUSBDeviceAuthorization(bad, a); !errors.Is(err, ErrUnsafePlan) {
				t.Fatalf("unsafe USB authorization accepted: %v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*USBAdmissionApproval){
		"unapproved": func(x *USBAdmissionApproval) { x.Valid = false },
		"old boot": func(x *USBAdmissionApproval) { x.BootID = "boot-B" },
		"old USB generation": func(x *USBAdmissionApproval) { x.DeviceGeneration = "usb-B" },
		"old guard": func(x *USBAdmissionApproval) { x.GuardDigest = "guard-B" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := a
			mutate(&bad)
			if err := PermitUSBDeviceAuthorization(e, bad); !errors.Is(err, ErrUnsafePlan) {
				t.Fatalf("stale approval accepted: %v", err)
			}
		})
	}
}
