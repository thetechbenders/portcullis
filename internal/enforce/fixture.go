package enforce

import "fmt"

// RenderTimedFixturePolicy is an explicitly UNSAFE, test-only policy. It
// authorizes IPv4 based solely on a source address and therefore does not
// establish identity or security against spoofing. NEVER deploy this policy
// on a guest network. The real enforcement design needs verified attachment
// identity, anti-spoofing and an independently persistent deny baseline.
//
// A kernel timeout set permits only guest -> fixture uplink traffic, while
// guest INPUT, guest -> protected LAN, and all guest IPv6 remain denied.
// The set begins EMPTY and is mutated only by the namespace test harness.
func RenderTimedFixturePolicy(guest, uplink string) (string, error) {
	if !safeInterface.MatchString(guest) || !safeInterface.MatchString(uplink) || guest == uplink {
		return "", ErrGuestInterface
	}
	return fmt.Sprintf(`table inet portcullis_guard {
    set test_allow_v4 {
        type ipv4_addr
        flags timeout
    }
    chain guest_input {
        type filter hook input priority -50; policy accept;
        iifname %q counter drop
    }
    chain guest_forward {
        type filter hook forward priority -50; policy accept;
        iifname %q oifname %q ip saddr @test_allow_v4 counter accept
        iifname %q counter drop
    }
}
`, guest, guest, uplink, guest), nil
}
