package enforce

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	guestA   = netip.MustParseAddr("10.203.0.100")
	guestMAC = model.MAC{2, 0, 0, 0, 0, 0x0a}
	// Every element batch line must be one of these shapes on this table.
	elementLine = regexp.MustCompile(`^(add element inet portcullis_guard (bound_v4|granted_v4|granted_dst_v4) \{ [0-9.]+( \. [0-9a-f:]{17})? timeout [0-9]+s \}|delete element inet portcullis_guard (bound_v4|granted_v4|granted_dst_v4) \{ [0-9.]+( \. [0-9a-f:]{17})? \}|flush set inet portcullis_guard (granted_v4|granted_dst_v4))$`)
)

func TestElementBatchesGolden(t *testing.T) {
	c := labGuard(t)
	grant, err := RenderGrant(c, guestA, guestMAC, 300*time.Second+900*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	const wantGrant = `add element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 1s }
delete element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a }
add element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 300s }
add element inet portcullis_guard granted_dst_v4 { 10.203.0.100 timeout 1s }
delete element inet portcullis_guard granted_dst_v4 { 10.203.0.100 }
add element inet portcullis_guard granted_dst_v4 { 10.203.0.100 timeout 300s }
`
	if grant != wantGrant {
		t.Fatalf("grant batch:\n%s", grant)
	}
	bind, _ := RenderBind(c, guestA, guestMAC, 2*time.Hour)
	unbind, _ := RenderUnbind(c, guestA, guestMAC)
	revoke, _ := RenderRevoke(c, guestA, guestMAC)
	revokeDst, _ := RenderRevokeDst(c, guestA)
	for name, tc := range map[string]struct{ got, want string }{
		"bind": {bind, "add element inet portcullis_guard bound_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 1s }\n" +
			"delete element inet portcullis_guard bound_v4 { 10.203.0.100 . 02:00:00:00:00:0a }\n" +
			"add element inet portcullis_guard bound_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 7200s }\n"},
		"unbind": {unbind, "add element inet portcullis_guard bound_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 1s }\n" +
			"delete element inet portcullis_guard bound_v4 { 10.203.0.100 . 02:00:00:00:00:0a }\n"},
		"revoke": {revoke, "add element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a timeout 1s }\n" +
			"delete element inet portcullis_guard granted_v4 { 10.203.0.100 . 02:00:00:00:00:0a }\n" +
			"add element inet portcullis_guard granted_dst_v4 { 10.203.0.100 timeout 1s }\n" +
			"delete element inet portcullis_guard granted_dst_v4 { 10.203.0.100 }\n"},
		"revoke dst": {revokeDst, "add element inet portcullis_guard granted_dst_v4 { 10.203.0.100 timeout 1s }\n" +
			"delete element inet portcullis_guard granted_dst_v4 { 10.203.0.100 }\n"},
		"flush": {RenderFlushGrants(), "flush set inet portcullis_guard granted_v4\nflush set inet portcullis_guard granted_dst_v4\n"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s batch:\n%s", name, tc.got)
		}
		for _, line := range strings.Split(strings.TrimSuffix(tc.got, "\n"), "\n") {
			if !elementLine.MatchString(line) {
				t.Errorf("%s: line touches more than set elements: %q", name, line)
			}
		}
	}
}

func TestElementBatchesRejectInvalidInput(t *testing.T) {
	c := labGuard(t)
	for _, ip := range []netip.Addr{
		{}, netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:10.203.0.100"), netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("127.0.0.1"), c.GatewayV4,
	} {
		if out, err := RenderGrant(c, ip, guestMAC, time.Minute); !errors.Is(err, ErrGuardElement) || out != "" {
			t.Errorf("grant %v: %q %v", ip, out, err)
		}
		if out, err := RenderRevokeDst(c, ip); !errors.Is(err, ErrGuardElement) || out != "" {
			t.Errorf("revoke dst %v: %q %v", ip, out, err)
		}
	}
	for _, mac := range []model.MAC{{}, {1, 0, 0x5e, 0, 0, 1}} {
		if _, err := RenderBind(c, guestA, mac, time.Minute); !errors.Is(err, ErrGuardElement) {
			t.Errorf("mac %v accepted: %v", mac, err)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second, 999 * time.Millisecond, MaxGrantTimeout + time.Second} {
		if _, err := RenderGrant(c, guestA, guestMAC, ttl); !errors.Is(err, ErrGuardElement) {
			t.Errorf("grant ttl %v accepted: %v", ttl, err)
		}
	}
	if _, err := RenderGrant(c, guestA, guestMAC, MaxGrantTimeout); err != nil {
		t.Errorf("max grant rejected: %v", err)
	}
	if _, err := RenderBind(c, guestA, guestMAC, MaxBindTimeout+time.Second); !errors.Is(err, ErrGuardElement) {
		t.Errorf("over-long bind accepted: %v", err)
	}
	// The only strings in a batch come from validated configuration.
	bad := c
	bad.Guest = "guest0 } flush ruleset; {"
	if out, err := RenderRevoke(bad, guestA, guestMAC); !errors.Is(err, ErrGuardConfig) || out != "" {
		t.Errorf("invalid config rendered %q: %v", out, err)
	}
}
