package enforce

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
	"github.com/thetechbenders/portcullis/internal/model"
)

func labGuard(t *testing.T) GuardConfig {
	t.Helper()
	c := GuardConfig{Guest: "guest0", Uplink: "uplink0", GuestIfIndex: 17, GatewayV4: netip.MustParseAddr("10.203.0.1"), PortalPort: 80, DNSPort: 53}
	for _, s := range config.DefaultProtectedV4 {
		c.Protected = append(c.Protected, netip.MustParsePrefix(s))
	}
	return c
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

const goldenBootstrap = `create table inet portcullis_guard
table inet portcullis_guard {
	set bound_v4 {
		type ipv4_addr . ether_addr
		size 1024
		flags timeout
	}
	set granted_v4 {
		type ipv4_addr . ether_addr
		size 1024
		flags timeout
	}
	set granted_dst_v4 {
		type ipv4_addr
		size 1024
		flags timeout
	}
	chain guest_input {
		type filter hook input priority -50; policy accept;
		iifname "guest0" iif 17 meta nfproto ipv4 udp sport 68 udp dport 67 counter accept comment "guest-dhcp"
		iifname "guest0" iif 17 ip daddr 10.203.0.1 ip saddr . ether saddr @bound_v4 udp dport 53 ct direction original counter accept comment "guest-dns"
		iifname "guest0" iif 17 ip daddr 10.203.0.1 ip saddr . ether saddr @bound_v4 tcp dport 80 ct direction original counter accept comment "guest-portal"
		iif 17 counter drop comment "guest-input"
		iifname "guest0" counter drop comment "guest-input-name"
	}
	chain guest_forward {
		type filter hook forward priority -50; policy accept;
		iifname "guest0" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } counter drop comment "guest-protected"
		iifname "guest0" iif 17 oifname "uplink0" ip saddr . ether saddr @granted_v4 counter accept comment "grant-egress"
		iif 17 counter drop comment "guest-egress"
		iifname "guest0" counter drop comment "guest-egress-name"
		iifname "uplink0" oifname "guest0" oif 17 ip daddr @granted_dst_v4 ct direction reply ct state established,related counter accept comment "grant-ingress"
		oif 17 counter drop comment "guest-ingress"
		oifname "guest0" counter drop comment "guest-ingress-name"
	}
	chain guest_output {
		type filter hook output priority -50; policy accept;
		oifname "guest0" oif 17 meta nfproto ipv4 udp sport 67 udp dport 68 counter accept comment "host-dhcp"
		oifname "guest0" oif 17 meta nfproto ipv4 ct state established,related counter accept comment "host-reply"
		oifname "guest0" oif 17 ip saddr 10.203.0.1 udp sport 53 counter accept comment "host-dns"
		oifname "guest0" oif 17 ip saddr 10.203.0.1 tcp sport 80 counter accept comment "host-portal"
		oif 17 counter drop comment "guest-output"
		oifname "guest0" counter drop comment "guest-output-name"
	}
}
`

// The final deny rules must remain bound to the same netdevice even after it
// is renamed. Name-based allows intentionally fail when the name changes.
func TestGuestDenyRulesPinKernelIndex(t *testing.T) {
	c := labGuard(t)
	got, err := RenderGuardBootstrap(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		`iif 17 counter drop comment "guest-input"`,
		`iif 17 counter drop comment "guest-egress"`,
		`oif 17 counter drop comment "guest-ingress"`,
		`oif 17 counter drop comment "guest-output"`,
	} {
		if !strings.Contains(got, rule) {
			t.Fatalf("missing index-pinned deny %q", rule)
		}
	}
	for _, allowed := range []string{
		`iifname "guest0" iif 17 meta nfproto`,
		`iifname "guest0" iif 17 ip daddr`,
		`iifname "guest0" iif 17 oifname "uplink0"`,
		`iifname "uplink0" oifname "guest0" oif 17`,
	} {
		if !strings.Contains(got, allowed) {
			t.Fatalf("guest authorization is not bound to both name and index: %q", allowed)
		}
	}
	for _, namedDeny := range []string{
		`iifname "guest0" counter drop comment "guest-input-name"`,
		`iifname "guest0" counter drop comment "guest-egress-name"`,
		`oifname "guest0" counter drop comment "guest-ingress-name"`,
		`oifname "guest0" counter drop comment "guest-output-name"`,
	} {
		if !strings.Contains(got, namedDeny) {
			t.Fatalf("missing complementary guest-name deny %q", namedDeny)
		}
	}
	c.GuestIfIndex = 0
	if out, err := RenderGuardBootstrap(c); !errors.Is(err, ErrGuardConfig) || out != "" {
		t.Fatalf("accepted missing guest ifindex: %q %v", out, err)
	}
}

func TestRenderGuardBootstrapGolden(t *testing.T) {
	got, err := RenderGuardBootstrap(labGuard(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenBootstrap {
		t.Fatalf("bootstrap drifted:\n%s", got)
	}
	for _, bad := range []string{"delete", "flush", "add table", "ct state established accept"} {
		if strings.Contains(got, bad) {
			t.Fatalf("bootstrap contains %q", bad)
		}
	}
	if !strings.HasPrefix(got, "create table inet portcullis_guard\ntable inet portcullis_guard {\n") ||
		strings.Count(got, "table inet") != 2 {
		t.Fatal("bootstrap must create the table exactly once before the block")
	}
}

func TestBootstrapAndVerifierShareRuleSpec(t *testing.T) {
	c := labGuard(t)
	got, _ := RenderGuardBootstrap(c)
	var lines []string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, " comment ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	rules := guardRules(c)
	wantOrder := []string{"guest-dhcp", "guest-dns", "guest-portal", "guest-input", "guest-input-name",
		"guest-protected", "grant-egress", "guest-egress", "guest-egress-name", "grant-ingress", "guest-ingress", "guest-ingress-name",
		"host-dhcp", "host-reply", "host-dns", "host-portal", "guest-output", "guest-output-name"}
	if len(rules) != len(wantOrder) || len(lines) != len(rules) {
		t.Fatalf("rule count: spec %d rendered %d", len(rules), len(lines))
	}
	for i, r := range rules {
		if r.comment != wantOrder[i] || lines[i] != r.text() {
			t.Fatalf("rule %d: spec %q rendered %q", i, r.text(), lines[i])
		}
	}
	// The real nft capture of this rendered guard yields exactly the spec's
	// counters, in spec order.
	state, err := VerifyGuardJSON(readFixture(t, "guard_empty_nft-1.0.9.json"), c)
	if err != nil {
		t.Fatal(err)
	}
	for i, ctr := range state.Counters {
		if ctr.Rule != wantOrder[i] {
			t.Fatalf("counter %d is %q", i, ctr.Rule)
		}
	}
}

func TestGuardRejectsInjection(t *testing.T) {
	base := labGuard(t)
	for name, mutate := range map[string]func(*GuardConfig){
		"guest quote":       func(c *GuardConfig) { c.Guest = `guest0" counter accept comment "x` },
		"guest newline":     func(c *GuardConfig) { c.Guest = "guest0\nflush ruleset" },
		"uplink semicolon":  func(c *GuardConfig) { c.Uplink = "up0;flush" },
		"same interfaces":   func(c *GuardConfig) { c.Uplink = c.Guest },
		"ipv6 gateway":      func(c *GuardConfig) { c.GatewayV4 = netip.MustParseAddr("fe80::1") },
		"mapped gateway":    func(c *GuardConfig) { c.GatewayV4 = netip.MustParseAddr("::ffff:10.203.0.1") },
		"broadcast gateway": func(c *GuardConfig) { c.GatewayV4 = netip.MustParseAddr("255.255.255.255") },
		"zero port":         func(c *GuardConfig) { c.DNSPort = 0 },
		"no protected":      func(c *GuardConfig) { c.Protected = nil },
		"non-canonical":     func(c *GuardConfig) { c.Protected = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/8")} },
		"overlap": func(c *GuardConfig) {
			c.Protected = append(c.Protected, netip.MustParsePrefix("10.1.0.0/16"))
		},
	} {
		c := base
		c.Protected = append([]netip.Prefix(nil), base.Protected...)
		mutate(&c)
		if out, err := RenderGuardBootstrap(c); !errors.Is(err, ErrGuardConfig) || out != "" {
			t.Errorf("%s: rendered %q err %v", name, out, err)
		}
		if _, err := VerifyGuardJSON(readFixture(t, "guard_empty_nft-1.0.9.json"), c); !errors.Is(err, ErrGuardAttestation) {
			t.Errorf("%s: verifier accepted invalid config: %v", name, err)
		}
	}
}

func TestVerifyGuardFixtures(t *testing.T) {
	c := labGuard(t)
	m := model.MAC{2, 0, 0, 0, 0, 0x0a}
	a := netip.MustParseAddr("10.203.0.100")
	s := func(n int) time.Duration { return time.Duration(n) * time.Second }

	empty, err := VerifyGuardJSON(readFixture(t, "guard_empty_nft-1.0.9.json"), c)
	if err != nil || len(empty.Bound)+len(empty.Granted)+len(empty.GrantedDst) != 0 || len(empty.Counters) != 18 {
		t.Fatalf("empty: %+v %v", empty, err)
	}
	got, err := VerifyGuardJSON(readFixture(t, "guard_elements_nft-1.0.9.json"), c)
	if err != nil {
		t.Fatal(err)
	}
	want := model.KernelState{
		Bound:      []model.Element{{Addr: a, MAC: m, Timeout: s(600), Expires: s(599)}},
		Granted:    []model.Element{{Addr: a, MAC: m, Timeout: s(300), Expires: s(299)}},
		GrantedDst: []model.Element{{Addr: a, Timeout: s(300), Expires: s(299)}},
		Counters:   empty.Counters,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("elements:\n got %+v\nwant %+v", got, want)
	}
	untimed, err := VerifyGuardJSON(readFixture(t, "guard_untimed_element_nft-1.0.9.json"), c)
	if err != nil || len(untimed.Granted) != 2 {
		t.Fatalf("untimed: %+v %v", untimed, err)
	}
	if e := untimed.Granted[1]; e.Addr != netip.MustParseAddr("10.203.0.101") || e.Timeout != 0 || e.Expires != 0 ||
		e.MAC != (model.MAC{2, 0, 0, 0, 0, 0x0b}) {
		t.Fatalf("untimed element must be reported with Timeout 0: %+v", e)
	}
	if _, err := VerifyGuardJSON(readFixture(t, "ruleset_dormant_truncated_nft-1.0.9.json"), c); !errors.Is(err, ErrGuardAttestation) {
		t.Fatalf("truncated listing accepted: %v", err)
	}
	// Equivalent protected coverage (nft's merged form, any order) is accepted.
	merged := c
	merged.Protected = append([]netip.Prefix{netip.MustParsePrefix("224.0.0.0/3")}, c.Protected[:8]...)
	if _, err := VerifyGuardJSON(readFixture(t, "guard_empty_nft-1.0.9.json"), merged); err != nil {
		t.Fatalf("equivalent protected set rejected: %v", err)
	}
}

// mutable returns the elements fixture as generic JSON and its entry list.
func mutable(t *testing.T) (map[string]any, []any) {
	t.Helper()
	v, err := parseStrictJSON(readFixture(t, "guard_elements_nft-1.0.9.json"), maxGuardJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	return doc, doc["nftables"].([]any)
}

func find(list []any, kind, key, value string) (int, map[string]any) {
	for i, e := range list {
		if body, ok := e.(map[string]any)[kind].(map[string]any); ok && body[key] == value {
			return i, body
		}
	}
	panic("fixture object not found: " + kind + " " + value)
}

func ruleExpr(list []any, comment string) []any {
	_, r := find(list, "rule", "comment", comment)
	return r["expr"].([]any)
}

func matchOf(expr []any, i int) map[string]any {
	return expr[i].(map[string]any)["match"].(map[string]any)
}

func TestVerifyGuardRejectsMutations(t *testing.T) {
	c := labGuard(t)
	swap := func(a, b string) func([]any) []any {
		return func(l []any) []any {
			i, _ := find(l, "rule", "comment", a)
			j, _ := find(l, "rule", "comment", b)
			l[i], l[j] = l[j], l[i]
			return l
		}
	}
	setElems := func(l []any, name string, elems ...any) {
		_, s := find(l, "set", "name", name)
		s["elem"] = elems
	}
	pair := func(ip, mac string) any { return map[string]any{"concat": []any{ip, mac}} }
	tests := map[string]func([]any) []any{
		"dormant table": func(l []any) []any {
			_, tb := find(l, "table", "name", GuardTable)
			tb["flags"] = []any{"dormant"}
			return l
		},
		"missing set":    func(l []any) []any { i, _ := find(l, "set", "name", SetGrantedDst); return append(l[:i], l[i+1:]...) },
		"wrong set type": func(l []any) []any { _, s := find(l, "set", "name", SetGranted); s["type"] = "ipv4_addr"; return l },
		"wrong set size": func(l []any) []any { _, s := find(l, "set", "name", SetBound); s["size"] = jnum(65535); return l },
		"set flags": func(l []any) []any {
			_, s := find(l, "set", "name", SetBound)
			s["flags"] = []any{"interval"}
			return l
		},
		"extra set key": func(l []any) []any { _, s := find(l, "set", "name", SetBound); s["timeout"] = jnum(3600); return l },
		"extra set": func(l []any) []any {
			return append(l, map[string]any{"set": map[string]any{"family": "inet", "table": GuardTable, "name": "evil", "handle": jnum(99)}})
		},
		"unhooked chain": func(l []any) []any {
			_, ch := find(l, "chain", "name", chainForward)
			for _, k := range []string{"type", "hook", "prio", "policy"} {
				delete(ch, k)
			}
			return l
		},
		"wrong hook": func(l []any) []any {
			_, ch := find(l, "chain", "name", chainForward)
			ch["hook"] = "prerouting"
			return l
		},
		"wrong priority":               func(l []any) []any { _, ch := find(l, "chain", "name", chainInput); ch["prio"] = jnum(0); return l },
		"wrong policy":                 func(l []any) []any { _, ch := find(l, "chain", "name", chainInput); ch["policy"] = "drop"; return l },
		"wrong type":                   func(l []any) []any { _, ch := find(l, "chain", "name", chainInput); ch["type"] = "route"; return l },
		"protected after grant-egress": swap("guest-protected", "grant-egress"),
		"grant after egress drop":      swap("grant-egress", "guest-egress"),
		"ingress drop first":           swap("grant-ingress", "guest-ingress"),
		"input drop first":             swap("guest-dhcp", "guest-input"),
		"missing rule": func(l []any) []any {
			i, _ := find(l, "rule", "comment", "guest-egress")
			return append(l[:i], l[i+1:]...)
		},
		"duplicate rule": func(l []any) []any { i, _ := find(l, "rule", "comment", "guest-input"); return append(l, l[i]) },
		"drop becomes accept": func(l []any) []any {
			e := ruleExpr(l, "guest-egress")
			e[len(e)-1] = map[string]any{"accept": nil}
			return l
		},
		"name-only guest-input deny": func(l []any) []any {
			matchOf(ruleExpr(l, "guest-input"), 0)["left"] = jmeta("iifname")
			return l
		},
		"name-only guest-egress deny": func(l []any) []any {
			matchOf(ruleExpr(l, "guest-egress"), 0)["left"] = jmeta("iifname")
			return l
		},
		"name-only guest-ingress deny": func(l []any) []any {
			matchOf(ruleExpr(l, "guest-ingress"), 0)["left"] = jmeta("oifname")
			return l
		},
		"guest grant loses index binding": func(l []any) []any {
			_, rule := find(l, "rule", "comment", "grant-egress")
			expr := rule["expr"].([]any)
			rule["expr"] = append(expr[:1:1], expr[2:]...)
			return l
		},
		"wrong iifname":  func(l []any) []any { matchOf(ruleExpr(l, "guest-input"), 0)["right"] = "guest1"; return l },
		"wrong oifname":  func(l []any) []any { matchOf(ruleExpr(l, "grant-egress"), 1)["right"] = "lan0"; return l },
		"wrong gateway":  func(l []any) []any { matchOf(ruleExpr(l, "guest-dns"), 1)["right"] = "10.203.0.2"; return l },
		"wrong dns port": func(l []any) []any { matchOf(ruleExpr(l, "guest-dns"), 3)["right"] = jnum(5353); return l },
		"wrong set ref":  func(l []any) []any { matchOf(ruleExpr(l, "grant-egress"), 2)["right"] = "@bound_v4"; return l },
		"missing ct direction": func(l []any) []any {
			_, r := find(l, "rule", "comment", "grant-ingress")
			e := r["expr"].([]any)
			r["expr"] = append(e[:3:3], e[4:]...)
			return l
		},
		"extra statement": func(l []any) []any {
			_, r := find(l, "rule", "comment", "guest-input")
			r["expr"] = append([]any{map[string]any{"log": nil}}, r["expr"].([]any)...)
			return l
		},
		"protected prefix removed": func(l []any) []any {
			set := matchOf(ruleExpr(l, "guest-protected"), 1)["right"].(map[string]any)
			set["set"] = set["set"].([]any)[1:]
			return l
		},
		"protected prefix narrowed": func(l []any) []any {
			set := matchOf(ruleExpr(l, "guest-protected"), 1)["right"].(map[string]any)["set"].([]any)
			set[1].(map[string]any)["prefix"].(map[string]any)["len"] = jnum(9)
			return l
		},
		"negative counter": func(l []any) []any {
			e := ruleExpr(l, "guest-input")
			e[1].(map[string]any)["counter"].(map[string]any)["packets"] = jnum(-1)
			return l
		},
		"flowtable object": func(l []any) []any {
			return append(l, map[string]any{"flowtable": map[string]any{"family": "inet", "table": GuardTable, "name": "ft", "handle": jnum(9)}})
		},
		"bad element mac": func(l []any) []any {
			setElems(l, SetGranted, pair("10.203.0.100", "03:00:00:00:00:0a"))
			return l
		},
		"bad element ip": func(l []any) []any { setElems(l, SetGranted, pair("::1", "02:00:00:00:00:0a")); return l },
		"gateway element": func(l []any) []any {
			setElems(l, SetBound, pair("10.203.0.1", "02:00:00:00:00:0a"))
			return l
		},
		"wrong element shape": func(l []any) []any { setElems(l, SetGrantedDst, pair("10.203.0.100", "02:00:00:00:00:0a")); return l },
		"fractional timeout": func(l []any) []any {
			setElems(l, SetGranted, map[string]any{"elem": map[string]any{"val": pair("10.203.0.100", "02:00:00:00:00:0a"), "timeout": json.Number("1.5")}})
			return l
		},
		"too many elements": func(l []any) []any {
			var elems []any
			for i := 0; i <= SetSize; i++ {
				elems = append(elems, netip.AddrFrom4([4]byte{10, 204, byte(i >> 8), byte(i)}).String())
			}
			setElems(l, SetGrantedDst, elems...)
			return l
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			doc, list := mutable(t)
			doc["nftables"] = mutate(list)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyGuardJSON(raw, c); !errors.Is(err, ErrGuardAttestation) {
				t.Fatalf("unsafe guard accepted: %v", err)
			}
		})
	}
	// Positive control: the unmutated round trip is accepted.
	doc, _ := mutable(t)
	raw, _ := json.Marshal(doc)
	if _, err := VerifyGuardJSON(raw, c); err != nil {
		t.Fatalf("round trip rejected: %v", err)
	}
}

func TestVerifyGuardRejectsMalformedAndForeignConfig(t *testing.T) {
	c := labGuard(t)
	good := readFixture(t, "guard_empty_nft-1.0.9.json")
	const duplicateTarget = `"family":"inet","name":"portcullis_guard"`
	if !strings.Contains(string(good), duplicateTarget) {
		t.Fatal("duplicate-key mutation target missing from fixture")
	}
	for name, data := range map[string][]byte{
		"truncated":     good[:len(good)/2],
		"trailing":      append(append([]byte{}, good...), []byte(`{}`)...),
		"duplicate key": []byte(strings.Replace(string(good), duplicateTarget, `"family":"inet","family":"inet","name":"portcullis_guard"`, 1)),
		"empty":         nil,
	} {
		if _, err := VerifyGuardJSON(data, c); !errors.Is(err, ErrGuardAttestation) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*GuardConfig){
		"guest":  func(g *GuardConfig) { g.Guest = "guest1" },
		"uplink": func(g *GuardConfig) { g.Uplink = "uplink1" },
		"portal": func(g *GuardConfig) { g.PortalPort = 8080 },
		"extra protected": func(g *GuardConfig) {
			g.Protected = append(append([]netip.Prefix{}, g.Protected...), netip.MustParsePrefix("198.18.0.0/15"))
		},
	} {
		g := c
		mutate(&g)
		if _, err := VerifyGuardJSON(good, g); !errors.Is(err, ErrGuardAttestation) {
			t.Errorf("guard for other config %s accepted: %v", name, err)
		}
	}
}
