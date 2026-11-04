//go:build netnslab

package enforce

import (
	"errors"
	"fmt"
)

// RenderTimedFixturePolicy is unsafe and exists ONLY for netns packet tests.
// A source IP is not authenticated identity. It must not ship in normal builds.
// This separate test table uses a kernel set to demonstrate packet grant and
// expiry mechanics, NOT the authority model of a production Portcullis.
func RenderTimedFixturePolicy(guest, uplink string) (string, error) {
	if !safeInterface.MatchString(guest) {
		return "", ErrGuestInterface
	}
	if !safeInterface.MatchString(uplink) || uplink == guest {
		return "", errors.New("fixture uplink must be a distinct valid interface")
	}
	return fmt.Sprintf(`table inet portcullis_lab {
    set test_allow_v4 {
        type ipv4_addr
        flags timeout
    }
    chain guest_input {
        type filter hook input priority -50; policy accept;
        iifname %q counter drop comment "guest-input"
    }
    chain guest_forward {
        type filter hook forward priority -50; policy accept;
        iifname %q oifname %q ip saddr @test_allow_v4 counter accept
        iifname %q counter drop comment "guest-egress"
        iifname %q oifname %q ip daddr @test_allow_v4 ct direction reply ct state established,related counter accept
        oifname %q counter drop comment "guest-ingress"
    }
}
`, guest, guest, uplink, guest, uplink, guest, guest), nil
}
