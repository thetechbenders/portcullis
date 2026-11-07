package hostpolicy

import (
	"errors"
	"fmt"
	"strings"
)

// USBAdmissionEvidence holds assertions from independent privileged readers.
// None of these booleans may be inferred from a device's vendor/product ID.
// This decision authorizes ONE kernel USB device configuration, not link UP.
type USBAdmissionEvidence struct {
	KernelDefaultDenyVerified bool
	DeviceCurrentlyUnauthorized bool
	PhysicalUSBIdentityVerified bool
	GuestCableDisconnected bool
	IndependentRecoveryVerified bool
	ManagementRoutePreserved bool
	UplinkOwnerVerified bool
	StrictEthernetExclusionVerified bool
	NoCompetingManager bool
	GuardInstalledAndAttested bool
	FirewallLifecycleSafe bool
	BootID string
	DeviceGeneration string
	GuardDigest string
}

// USBAdmissionApproval is an explicit one-shot approval bound to the observed
// boot, USB generation and guard digest. Replug and reboot invalidate it.
type USBAdmissionApproval struct {
	Valid bool
	BootID string
	DeviceGeneration string
	GuardDigest string
}

// PermitUSBDeviceAuthorization is a pure decision helper. It must be called
// immediately before a separately implemented privileged USB authorization
// action, with fresh evidence and explicit operator approval. A true result
// is NOT permission to raise the network interface or connect guest RJ45.
func PermitUSBDeviceAuthorization(e USBAdmissionEvidence, a USBAdmissionApproval) error {
	if !e.KernelDefaultDenyVerified || !e.DeviceCurrentlyUnauthorized ||
		!e.PhysicalUSBIdentityVerified || !e.GuestCableDisconnected ||
		!e.IndependentRecoveryVerified || !e.ManagementRoutePreserved ||
		!e.UplinkOwnerVerified || !e.StrictEthernetExclusionVerified ||
		!e.NoCompetingManager || !e.GuardInstalledAndAttested ||
		!e.FirewallLifecycleSafe {
		return fmt.Errorf("%w: kernel USB authorization prerequisites are unverified", ErrUnsafePlan)
	}
	if !a.Valid || strings.TrimSpace(e.BootID) == "" ||
		strings.TrimSpace(e.DeviceGeneration) == "" ||
		strings.TrimSpace(e.GuardDigest) == "" ||
		a.BootID != e.BootID ||
		a.DeviceGeneration != e.DeviceGeneration ||
		a.GuardDigest != e.GuardDigest {
		return fmt.Errorf("%w: USB approval missing, stale, or from another generation", ErrUnsafePlan)
	}
	return nil
}

var _ = errors.Is
