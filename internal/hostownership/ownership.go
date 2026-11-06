// Package hostownership is a pure eligibility gate for a dedicated physical
// guest NIC. It never edits host networking or authorizes a deployment by itself.
package hostownership

import (
 "slices"
 "strings"
)

// Identity must be independently read from the physical device, including the
// permanent MAC. The existing passive host inventory cannot yet supply it.
type Identity struct {
 Name, Parent, CurrentMAC, PermanentMAC, Driver, VendorID, ProductID string
}
type Plan struct {
 Guest Identity
 Uplink, Management string
}
// Observed values are pointers: unknown is never silently interpreted as safe.
type Observation struct {
 Guest *Identity
 Down, IPv6Disabled, AcceptRAZero *bool
 Carrier, HasAddresses, HasRoutes, Enslaved *bool
 NetworkManagerMayActivate, OtherManagerMayActivate *bool
 ManagementPreserved, ManagementRoutePreserved *bool
 IsolatedPeer, GuardAttested, UnknownIngressDenied *bool
 GuestInputDenied, GuestOutputDenied, BypassAttested *bool
 KernelCompatible, RecoveryVerified *bool
 BootID, PlanDigest, GuardDigest, NetdevGeneration string
 Approval *Approval
}
// Approval.Valid is ONLY accepted from a future trusted verifier that has
// checked operator authority and expiry. Do not populate from user input.
type Approval struct {
 Valid bool
 BootID, PlanDigest, GuardDigest, NetdevGeneration string
}
type Decision struct {
 MayRequestGuestUp bool
 Reasons []string
}
func yes(v *bool) bool { return v != nil && *v }
func no(v *bool) bool { return v != nil && !*v }
func identityMatches(p Identity, g *Identity) bool {
 if g == nil { return false }
 for _, s := range []string{p.Name,p.Parent,p.CurrentMAC,p.PermanentMAC,p.Driver,p.VendorID,p.ProductID,g.Name,g.Parent,g.CurrentMAC,g.PermanentMAC,g.Driver,g.VendorID,g.ProductID} {
  if strings.TrimSpace(s)=="" {return false}
 }
 return p.Name==g.Name && p.Parent==g.Parent &&
 strings.EqualFold(p.CurrentMAC,g.CurrentMAC) &&
 strings.EqualFold(p.PermanentMAC,g.PermanentMAC) &&
 p.Driver==g.Driver && strings.EqualFold(p.VendorID,g.VendorID) &&
 strings.EqualFold(p.ProductID,g.ProductID)
}
// Evaluate only checks whether a future privileged adapter could REQUEST
// exposure after it independently revalidates every prerequisite. It does
// not install a guard, raise an interface, or prove physical isolation.
// A missing field, matcher miss, hotplug, rename or lost attestation fails shut.
func Evaluate(p Plan, o Observation) Decision {
 var reasons []string
 fail:=func(code string){reasons=append(reasons,code)}
 if p.Guest.Name=="" || p.Uplink=="" || p.Management=="" ||
 p.Guest.Name==p.Uplink || p.Guest.Name==p.Management || p.Uplink==p.Management {
  fail("roles_invalid")
 }
 if !identityMatches(p.Guest,o.Guest) {fail("identity_unverified")}
 if !yes(o.Down) {fail("guest_down_unverified")}
 if !yes(o.IPv6Disabled) || !yes(o.AcceptRAZero) {fail("ipv6_unrestricted")}
 if !no(o.Carrier) || !no(o.HasAddresses) || !no(o.HasRoutes) || !no(o.Enslaved) {fail("guest_topology_unverified")}
 if !no(o.NetworkManagerMayActivate) || !no(o.OtherManagerMayActivate) {fail("manager_exclusivity_unverified")}
 if !yes(o.ManagementPreserved) || !yes(o.ManagementRoutePreserved) {fail("management_unverified")}
 if !yes(o.IsolatedPeer) {fail("peer_unverified")}
 if !yes(o.GuardAttested) || !yes(o.UnknownIngressDenied) ||
 !yes(o.GuestInputDenied) || !yes(o.GuestOutputDenied) ||
 !yes(o.BypassAttested) || !yes(o.KernelCompatible) {fail("guard_unverified")}
 if !yes(o.RecoveryVerified) {fail("recovery_unverified")}
 a:=o.Approval
 if a==nil || !a.Valid || o.BootID=="" || o.PlanDigest=="" ||
 o.GuardDigest=="" || o.NetdevGeneration=="" ||
 a.BootID!=o.BootID || a.PlanDigest!=o.PlanDigest ||
 a.GuardDigest!=o.GuardDigest || a.NetdevGeneration!=o.NetdevGeneration {
  fail("approval_unverified")
 }
 slices.Sort(reasons)
 return Decision{MayRequestGuestUp:len(reasons)==0, Reasons:reasons}
}
// FaultEvidence distinguishes unconfirmed exposure isolation from an attested
// guard. Kernel grants can remain live after SIGKILL until kernel expiry.
type FaultEvidence struct {
 GuardAttested, AdminDownConfirmed, IsolationUnconfirmed bool
 ExistingKernelGrantsMayRemain bool
}
func OnFault(guardAttested, adminDownReadback bool) FaultEvidence {
 return FaultEvidence{GuardAttested:guardAttested,
 AdminDownConfirmed:adminDownReadback,
 IsolationUnconfirmed:!adminDownReadback,
 ExistingKernelGrantsMayRemain:true}
}
