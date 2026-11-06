// Package hostownership evaluates the safety prerequisites for a dedicated
// physical guest NIC. It is a pure, non-privileged policy gate: it never edits
// interfaces, sysctls, firewalls, NetworkManager, routes, or services.
//
// Its decisions are deliberately insufficient for physical activation: a
// separate privileged adapter and operator-controlled hardware acceptance
// procedure must enforce and attest the corresponding kernel state.
package hostownership

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"slices"
	"strings"
)

// DeviceIdentity must be independently observed, never inferred solely from a
// Linux interface name. The permanent MAC must come from an independent source
// and is not obtained by the current passive hostpreflight inventory.
type DeviceIdentity struct {
	Name         string
	SysfsParent  string
	CurrentMAC   string
	PermanentMAC string
	Driver       string
	USBVendor    string
	USBProduct   string
}

// Plan names explicit, disjoint device roles. No default-interface or route
// discovery is permitted to fill in a missing role.
type Plan struct {
	Guest          DeviceIdentity
	UplinkName     string
	ManagementName string
}

// Observation is a single, potentially stale view supplied by a future host
// adapter. All booleans use *bool so absence of evidence cannot mean false.
// Sensitive physical identifiers must remain in restricted, private evidence.
type Observation struct {
	Guest                       *DeviceIdentity
	GuestAdministrativelyDown   *bool
	GuestIPv6Disabled           *bool
	GuestAcceptRAZero           *bool
	GuestHasAddresses           *bool
	GuestHasRoutes              *bool
	GuestEnslaved               *bool
	GuestCarrier                *bool
	ManagerMayActivate          *bool
	CompetingManagerMayActivate *bool
	GuestInterfaceGeneration    string
	ManagementPathPreserved     *bool
	ManagementRoutePreserved    *bool
	IsolatedUplinkPeer          *bool
	GuardAttested               *bool
	GuardBlocksUnknownIngress   *bool
	GuardBlocksGuestInput       *bool
	GuardBlocksGuestOutput      *bool
	BypassPathsAttested         *bool
	KernelTargetCompatible      *bool
	LocalRecoveryVerified       *bool
	EvidenceFresh               *bool
	// These identifiers are supplied by a trusted observation layer. Approval
	// authenticity, expiry and replay protection are verified by that layer.
	BootID      string
	GuardDigest string
	Approval    *Approval
}

// EvidenceFresh is supplied only by a trusted observation layer that has
// verified bounded age and continuous identity/guard state. It must never be
// derived from a browser or untrusted JSON. A stale snapshot fails closed.
//
// Approval is an independently issued operator decision. The caller must
// validate its authenticity, expiry and non-replay before setting Valid true.
// Evaluate checks the plan digest computed from the actual Plan, plus boot,
// guard and netdev-generation bindings; Valid alone is not authentication.
type Approval struct {
	Valid                    bool
	BootID                   string
	PlanDigest               string
	GuardDigest              string
	GuestInterfaceGeneration string
}

// Decision is a fail-closed request to a future independent adapter, NOT a
// claim that the link is physically isolated or that the current guard works.
type Decision struct {
	MayRequestGuestUp bool
	Reasons           []string
}

// PlanDigest derives a versioned, domain-separated SHA-256 binding from every
// current Plan field. The approval issuer must independently authenticate the
// request and use this digest for the exact approved plan.
func PlanDigest(p Plan) string {
	payload, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("portcullis-hostownership-plan-v1\x00"), payload...))
	return hex.EncodeToString(sum[:])
}

func yes(b *bool) bool { return b != nil && *b }
func no(b *bool) bool  { return b != nil && !*b }

func validMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
			return true
		}
	}
	return false
}

func sameIdentity(want DeviceIdentity, got *DeviceIdentity) bool {
	if got == nil {
		return false
	}
	// Require all identity fields, including independently measured permanent
	// MAC. A name or generic chipset ID is never sufficient.
	for _, v := range []string{want.Name, want.SysfsParent, want.CurrentMAC, want.PermanentMAC, want.Driver, want.USBVendor, want.USBProduct,
		got.Name, got.SysfsParent, got.CurrentMAC, got.PermanentMAC, got.Driver, got.USBVendor, got.USBProduct} {
		if strings.TrimSpace(v) == "" {
			return false
		}
	}
	if !validMAC(want.CurrentMAC) || !validMAC(want.PermanentMAC) || !validMAC(got.CurrentMAC) || !validMAC(got.PermanentMAC) {
		return false
	}
	return want.Name == got.Name && want.SysfsParent == got.SysfsParent &&
		strings.EqualFold(want.CurrentMAC, got.CurrentMAC) &&
		strings.EqualFold(want.PermanentMAC, got.PermanentMAC) &&
		want.Driver == got.Driver && strings.EqualFold(want.USBVendor, got.USBVendor) &&
		strings.EqualFold(want.USBProduct, got.USBProduct)
}

// Evaluate requires fresh, independent proof of every prerequisite. It never
// produces mutating actions. A missed NetworkManager exclusion, replug,
// rename, guard flush, or unknown state cannot authorize UP when the trusted
// observer reports the corresponding evidence accurately.
func Evaluate(p Plan, o Observation) Decision {
	var reasons []string
	fail := func(code string) { reasons = append(reasons, code) }
	if strings.TrimSpace(p.Guest.Name) == "" || strings.TrimSpace(p.UplinkName) == "" || strings.TrimSpace(p.ManagementName) == "" ||
		p.Guest.Name == p.UplinkName || p.Guest.Name == p.ManagementName || p.UplinkName == p.ManagementName {
		fail("invalid_roles")
	}
	if !sameIdentity(p.Guest, o.Guest) {
		fail("guest_identity_unverified")
	}
	if !yes(o.GuestAdministrativelyDown) {
		fail("guest_not_confirmed_down")
	}
	if !yes(o.GuestIPv6Disabled) || !yes(o.GuestAcceptRAZero) {
		fail("guest_ipv6_not_restricted")
	}
	if !no(o.GuestHasAddresses) || !no(o.GuestHasRoutes) || !no(o.GuestEnslaved) || !no(o.GuestCarrier) {
		fail("guest_topology_unverified")
	}
	if !no(o.ManagerMayActivate) || !no(o.CompetingManagerMayActivate) {
		fail("manager_exclusivity_unverified")
	}
	if !yes(o.ManagementPathPreserved) || !yes(o.ManagementRoutePreserved) {
		fail("management_not_preserved")
	}
	if !yes(o.IsolatedUplinkPeer) {
		fail("uplink_peer_not_attested")
	}
	if !yes(o.GuardAttested) || !yes(o.GuardBlocksUnknownIngress) ||
		!yes(o.GuardBlocksGuestInput) || !yes(o.GuardBlocksGuestOutput) ||
		!yes(o.BypassPathsAttested) || !yes(o.KernelTargetCompatible) {
		fail("guard_or_bypass_unverified")
	}
	if !yes(o.LocalRecoveryVerified) {
		fail("recovery_unverified")
	}
	if !yes(o.EvidenceFresh) {
		fail("evidence_stale")
	}
	if o.Approval == nil || !o.Approval.Valid || strings.TrimSpace(o.BootID) == "" || strings.TrimSpace(o.GuardDigest) == "" || strings.TrimSpace(o.GuestInterfaceGeneration) == "" ||
		strings.TrimSpace(o.Approval.BootID) == "" || strings.TrimSpace(o.Approval.PlanDigest) == "" || strings.TrimSpace(o.Approval.GuardDigest) == "" || strings.TrimSpace(o.Approval.GuestInterfaceGeneration) == "" ||
		o.Approval.BootID != o.BootID || o.Approval.PlanDigest != PlanDigest(p) ||
		o.Approval.GuardDigest != o.GuardDigest || o.Approval.GuestInterfaceGeneration != o.GuestInterfaceGeneration {
		fail("approval_unverified")
	}
	slices.Sort(reasons)
	return Decision{MayRequestGuestUp: len(reasons) == 0, Reasons: reasons}
}

// RuntimeState separates the presence of an attested guard from an observed
// closed link. It never labels an unknown link state physically isolated.
type RuntimeState struct {
	GuardAttested                 bool
	AdminDownConfirmed            bool
	IsolationUnconfirmed          bool
	ExistingKernelGrantsMayRemain bool
}

// OnFault reports a point-in-time administrative DOWN readback, not sustained
// physical isolation or proof that a privileged actor enforced it. Existing grants may outlive a controller crash,
// bounded by their kernel timeout (currently at most fifteen minutes).
func OnFault(guardAttested, adminDownReadback bool) RuntimeState {
	return RuntimeState{
		GuardAttested:                 guardAttested,
		AdminDownConfirmed:            adminDownReadback,
		IsolationUnconfirmed:          !adminDownReadback,
		ExistingKernelGrantsMayRemain: true,
	}
}
