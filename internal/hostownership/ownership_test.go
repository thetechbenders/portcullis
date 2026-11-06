package hostownership

import (
	"slices"
	"testing"
)

func ptr(v bool) *bool { return &v }

func baseline() (Plan, Observation) {
	id := DeviceIdentity{"usb-guest", "/sys/devices/pci0000/usb1", "02:11:22:33:44:55", "02:11:22:33:44:55", "r8152", "0bda", "8156"}
	p := Plan{Guest: id, UplinkName: "eth0", ManagementName: "wlan0"}
	o := Observation{
		Guest: &id, GuestAdministrativelyDown: ptr(true), GuestIPv6Disabled: ptr(true), GuestAcceptRAZero: ptr(true),
		GuestHasAddresses: ptr(false), GuestHasRoutes: ptr(false), GuestEnslaved: ptr(false), GuestCarrier: ptr(false),
		ManagerMayActivate: ptr(false), CompetingManagerMayActivate: ptr(false),
		ManagementPathPreserved: ptr(true), ManagementRoutePreserved: ptr(true), IsolatedUplinkPeer: ptr(true),
		GuardAttested: ptr(true), GuardBlocksUnknownIngress: ptr(true), GuardBlocksGuestInput: ptr(true),
		GuardBlocksGuestOutput: ptr(true), BypassPathsAttested: ptr(true), KernelTargetCompatible: ptr(true),
		LocalRecoveryVerified: ptr(true), BootID: "boot-test", PlanDigest: "plan-test", GuardDigest: "guard-test",
		GuestInterfaceGeneration: "netdev-instance-test",
	}
	o.Approval = &Approval{Valid: true, BootID: o.BootID, PlanDigest: o.PlanDigest, GuardDigest: o.GuardDigest, GuestInterfaceGeneration: o.GuestInterfaceGeneration}
	return p, o
}

func TestFullyAttestedFixture(t *testing.T) {
	p, o := baseline()
	if got := Evaluate(p, o); !got.MayRequestGuestUp || len(got.Reasons) != 0 {
		t.Fatalf("expected policy eligibility in synthetic fixture, got %#v", got)
	}
}

func TestDefaultFailsClosed(t *testing.T) {
	p, _ := baseline()
	got := Evaluate(p, Observation{})
	if got.MayRequestGuestUp || len(got.Reasons) == 0 {
		t.Fatalf("zero evidence authorized: %#v", got)
	}
}

func TestOneFaultNeverAuthorizes(t *testing.T) {
	cases := map[string]func(*Plan, *Observation){
		"guest up":                  func(_ *Plan, o *Observation) { o.GuestAdministrativelyDown = ptr(false) },
		"missing link readback":     func(_ *Plan, o *Observation) { o.GuestAdministrativelyDown = nil },
		"ipv6 enabled":              func(_ *Plan, o *Observation) { o.GuestIPv6Disabled = ptr(false) },
		"ra enabled":                func(_ *Plan, o *Observation) { o.GuestAcceptRAZero = ptr(false) },
		"ipv6 unknown after replug": func(_ *Plan, o *Observation) { o.GuestIPv6Disabled = nil },
		"guest cable connected":     func(_ *Plan, o *Observation) { o.GuestCarrier = ptr(true) },
		"unknown cable state":       func(_ *Plan, o *Observation) { o.GuestCarrier = nil },
		"unexpected address":        func(_ *Plan, o *Observation) { o.GuestHasAddresses = ptr(true) },
		"unexpected route":          func(_ *Plan, o *Observation) { o.GuestHasRoutes = ptr(true) },
		"bridge membership":         func(_ *Plan, o *Observation) { o.GuestEnslaved = ptr(true) },
		"nm matcher miss":           func(_ *Plan, o *Observation) { o.ManagerMayActivate = ptr(true) },
		"manager unknown":           func(_ *Plan, o *Observation) { o.ManagerMayActivate = nil },
		"alternative manager":       func(_ *Plan, o *Observation) { o.CompetingManagerMayActivate = ptr(true) },
		"management bounce":         func(_ *Plan, o *Observation) { o.ManagementPathPreserved = ptr(false) },
		"management route lost":     func(_ *Plan, o *Observation) { o.ManagementRoutePreserved = ptr(false) },
		"unverified peer":           func(_ *Plan, o *Observation) { o.IsolatedUplinkPeer = nil },
		"guard removed":             func(_ *Plan, o *Observation) { o.GuardAttested = ptr(false) },
		"rename hole":               func(_ *Plan, o *Observation) { o.GuardBlocksUnknownIngress = ptr(false) },
		"guest INPUT hole":          func(_ *Plan, o *Observation) { o.GuardBlocksGuestInput = ptr(false) },
		"host OUTPUT hole":          func(_ *Plan, o *Observation) { o.GuardBlocksGuestOutput = ptr(false) },
		"bypass unknown":            func(_ *Plan, o *Observation) { o.BypassPathsAttested = nil },
		"kernel mismatch":           func(_ *Plan, o *Observation) { o.KernelTargetCompatible = ptr(false) },
		"recovery missing":          func(_ *Plan, o *Observation) { o.LocalRecoveryVerified = ptr(false) },
		"replug new instance":       func(_ *Plan, o *Observation) { o.GuestInterfaceGeneration = "replug-2" },
		"boot changed":              func(_ *Plan, o *Observation) { o.BootID = "different-boot" },
		"guard changed":             func(_ *Plan, o *Observation) { o.GuardDigest = "new-guard" },
		"plan changed":              func(_ *Plan, o *Observation) { o.PlanDigest = "new-plan" },
		"expired approval":          func(_ *Plan, o *Observation) { o.Approval.Valid = false },
		"missing approval":          func(_ *Plan, o *Observation) { o.Approval = nil },
		"interface rename":          func(_ *Plan, o *Observation) { o.Guest.Name = "enx-renamed" },
		"sysfs port move":           func(_ *Plan, o *Observation) { o.Guest.SysfsParent = "/sys/devices/other-port" },
		"driver rebind":             func(_ *Plan, o *Observation) { o.Guest.Driver = "cdc_ncm" },
		"permanent mac mismatch":    func(_ *Plan, o *Observation) { o.Guest.PermanentMAC = "02:11:22:33:44:66" },
		"current mac mismatch":      func(_ *Plan, o *Observation) { o.Guest.CurrentMAC = "02:11:22:33:44:66" },
		"missing permanent mac":     func(_ *Plan, o *Observation) { o.Guest.PermanentMAC = "" },
		"no driver":                 func(_ *Plan, o *Observation) { o.Guest.Driver = "" },
		"wrong vid":                 func(_ *Plan, o *Observation) { o.Guest.USBVendor = "ffff" },
		"role collision":            func(p *Plan, _ *Observation) { p.UplinkName = p.ManagementName },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, o := baseline()
			change(&p, &o)
			got := Evaluate(p, o)
			if got.MayRequestGuestUp || len(got.Reasons) == 0 {
				t.Fatalf("fault authorized guest UP: %#v", got)
			}
			if !slices.IsSorted(got.Reasons) {
				t.Fatalf("unstable reason order: %#v", got)
			}
		})
	}
}

func TestFaultReadbackNeverInventsIsolation(t *testing.T) {
	for _, down := range []bool{false, true} {
		s := OnFault(false, down)
		if s.GuardAttested || s.AdminDownConfirmed != down || s.IsolationUnconfirmed == down || !s.ExistingKernelGrantsMayRemain {
			t.Fatalf("incorrect crash-state evidence: %#v", s)
		}
	}
}

func TestCandidateDoesNotMeanActive(t *testing.T) {
	p, o := baseline()
	o.GuestAdministrativelyDown = ptr(false)
	// The adapter may only ask for activation when it has separately verified
	// DOWN beforehand; an already active guest cannot bootstrap this gate.
	if Evaluate(p, o).MayRequestGuestUp {
		t.Fatal("already-exposed guest must be rejected")
	}
}
