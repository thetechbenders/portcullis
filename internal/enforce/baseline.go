// Package enforce describes firewall policies without installing them.
// Phase 2 provides a guest isolation baseline, not a production installer.
package enforce

import (
	"errors"
	"fmt"
	"regexp"
)

var ErrGuestInterface = errors.New("guest interface must be a valid Linux interface name (1-15 safe ASCII bytes)")

var safeInterface = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

// RenderDenyBaseline returns an atomic, convergent nftables batch for this
// project's owned table. Both INPUT from guests and FORWARD in either
// direction are denied for IPv4 and IPv6, including established traffic.
//
// The add/delete/redefine sequence is a SINGLE nft transaction when sent
// through one nft -f invocation; NEVER execute its statements separately.
// It removes stale sets and grants in this table. This is still inert text,
// not a production installer: table ownership, interface identity, hook
// bypasses and persistence require independent deployment controls.
func RenderDenyBaseline(guestInterface string) (string, error) {
	if !safeInterface.MatchString(guestInterface) {
		return "", ErrGuestInterface
	}
	// 'add table' is harmless if it exists, and establishes an empty table
	// when missing so the following delete succeeds. All operations in one
	// nft -f batch are committed atomically or not at all.
	return fmt.Sprintf(`add table inet portcullis_guard
delete table inet portcullis_guard
table inet portcullis_guard {
    chain guest_input {
        type filter hook input priority -50; policy accept;
        iifname %q counter drop
    }
    chain guest_forward {
        type filter hook forward priority -50; policy accept;
        iifname %q counter drop
        oifname %q counter drop
    }
}
`, guestInterface, guestInterface, guestInterface), nil
}
