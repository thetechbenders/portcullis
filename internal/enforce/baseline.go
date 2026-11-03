// Package enforce describes firewall policies without installing them.
// Phase 2 initially provides only a fail-closed deny baseline.
package enforce

import (
	"errors"
	"fmt"
	"regexp"
)

var ErrGuestInterface = errors.New("guest interface must be a valid Linux interface name (1-15 safe ASCII bytes)")

var safeInterface = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

// RenderDenyBaseline generates an nftables inet ruleset fragment for a
// dedicated guest interface. Both host INPUT and routed FORWARD are dropped,
// for IPv4 and IPv6, regardless of conntrack state.
//
// IMPORTANT: This is inert text, not a firewall installer. It grants no
// network access, including DHCP/DNS/portal. Before deployment, the operator
// must inspect all existing rules and provision a reliable recovery path.
// The table is persistent by deployment policy; never use an owner-scoped
// transient nftables table as the only deny boundary.
func RenderDenyBaseline(guestInterface string) (string, error) {
	if !safeInterface.MatchString(guestInterface) {
		return "", ErrGuestInterface
	}

	// nftables base chains can coexist: an accept in some other chain does
	// not cancel a drop here. The accept policy applies only when the packet
	// does not enter from the dedicated guest interface.
	return fmt.Sprintf(`table inet portcullis_guard {
    chain guest_input {
        type filter hook input priority -50; policy accept;
        iifname %q counter drop
    }
    chain guest_forward {
        type filter hook forward priority -50; policy accept;
        iifname %q counter drop
    }
}
`, guestInterface, guestInterface), nil
}
