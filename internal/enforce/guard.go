package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
)

// Names of the persistent guard objects.
const (
	GuardTable    = "portcullis_guard"
	SetBound      = "bound_v4"
	SetGranted    = "granted_v4"
	SetGrantedDst = "granted_dst_v4"
)

// Kernel timeout bounds and set capacity.
const (
	MaxGrantTimeout = 15 * time.Minute
	MaxBindTimeout  = 2 * time.Hour
	SetSize         = 1024
)

const (
	maxProtectedPrefixes = 64
	guardPriority        = -50
	chainInput           = "guest_input"
	chainForward         = "guest_forward"
)

// ErrGuardConfig rejects a guard description that cannot be rendered or
// attested safely.
var ErrGuardConfig = errors.New("invalid portcullis guard configuration")

// GuardConfig is the typed input to every guard renderer and verifier.
type GuardConfig struct {
	Guest, Uplink       string
	GatewayV4           netip.Addr
	PortalPort, DNSPort uint16
	Protected           []netip.Prefix
}

// GuardConfigFrom extracts the guard description from a validated config.
func GuardConfigFrom(c *config.Config) GuardConfig {
	if c == nil {
		return GuardConfig{}
	}
	return GuardConfig{
		Guest: c.GuestInterface, Uplink: c.UplinkInterface, GatewayV4: c.GatewayV4,
		PortalPort: c.PortalPort, DNSPort: c.DNSPort, Protected: slices.Clone(c.ProtectedV4),
	}
}

// Validate rejects anything that could not be rendered as literal nft text
// without quoting ambiguity. Interface names are the only strings rendered.
func (c GuardConfig) Validate() error {
	if !safeInterface.MatchString(c.Guest) || !safeInterface.MatchString(c.Uplink) {
		return fmt.Errorf("%w: interface names must be 1-15 safe ASCII bytes", ErrGuardConfig)
	}
	if c.Guest == c.Uplink {
		return fmt.Errorf("%w: guest and uplink interfaces must differ", ErrGuardConfig)
	}
	if !c.GatewayV4.Is4() || !c.GatewayV4.IsGlobalUnicast() {
		return fmt.Errorf("%w: gateway must be a unicast IPv4 address", ErrGuardConfig)
	}
	if c.PortalPort == 0 || c.DNSPort == 0 {
		return fmt.Errorf("%w: portal and DNS ports must be nonzero", ErrGuardConfig)
	}
	if len(c.Protected) == 0 || len(c.Protected) > maxProtectedPrefixes {
		return fmt.Errorf("%w: 1-%d protected prefixes required", ErrGuardConfig, maxProtectedPrefixes)
	}
	for i, p := range c.Protected {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
			return fmt.Errorf("%w: protected prefixes must be canonical IPv4 prefixes", ErrGuardConfig)
		}
		for _, q := range c.Protected[:i] {
			if p.Overlaps(q) {
				return fmt.Errorf("%w: protected prefixes overlap", ErrGuardConfig)
			}
		}
	}
	return nil
}

// guardTerm is one match of a guard rule: its nft source text and the JSON
// expression nft lists for it. Renderer and verifier both derive from the
// same guardRules specification so they cannot drift apart.
type guardTerm struct {
	text string
	expr any
	// rangeSet marks the protected destination match, whose "right" side is
	// compared as a normalized IPv4 range set because nft merges intervals.
	rangeSet bool
}

type guardRule struct {
	chain, comment string
	terms          []guardTerm
	verdict        string
}

func (r guardRule) text() string {
	parts := make([]string, 0, len(r.terms)+3)
	for _, t := range r.terms {
		parts = append(parts, t.text)
	}
	return strings.Join(parts, " ") + " counter " + r.verdict + ` comment "` + r.comment + `"`
}

var guardChains = []struct{ name, hook string }{{chainInput, "input"}, {chainForward, "forward"}}

type guardSet struct {
	name, typeText string
	typeJSON       any
	concat         bool
}

var guardSets = []guardSet{
	{SetBound, "ipv4_addr . ether_addr", []any{"ipv4_addr", "ether_addr"}, true},
	{SetGranted, "ipv4_addr . ether_addr", []any{"ipv4_addr", "ether_addr"}, true},
	{SetGrantedDst, "ipv4_addr", "ipv4_addr", false},
}

func jnum(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func jmatch(op string, left, right any) any {
	return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
}

func jmeta(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }

func jpayload(proto, field string) any {
	return map[string]any{"payload": map[string]any{"protocol": proto, "field": field}}
}

func termIfname(key, name string) guardTerm {
	return guardTerm{text: key + ` "` + name + `"`, expr: jmatch("==", jmeta(key), name)}
}

func termPort(proto, field string, port uint16) guardTerm {
	return guardTerm{
		text: fmt.Sprintf("%s %s %d", proto, field, port),
		expr: jmatch("==", jpayload(proto, field), jnum(int64(port))),
	}
}

func termSourcePair(set string) guardTerm {
	left := map[string]any{"concat": []any{jpayload("ip", "saddr"), jpayload("ether", "saddr")}}
	return guardTerm{text: "ip saddr . ether saddr @" + set, expr: jmatch("==", left, "@"+set)}
}

func termProtected(prefixes []netip.Prefix) guardTerm {
	texts := make([]string, 0, len(prefixes))
	set := make([]any, 0, len(prefixes))
	for _, p := range prefixes {
		texts = append(texts, p.String())
		set = append(set, map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": jnum(int64(p.Bits()))}})
	}
	return guardTerm{
		text:     "ip daddr { " + strings.Join(texts, ", ") + " }",
		expr:     jmatch("==", jpayload("ip", "daddr"), map[string]any{"set": set}),
		rangeSet: true,
	}
}

// guardRules is the single ordered rule specification. ORDER IS SECURITY
// RELEVANT: guest-protected must precede grant-egress, and every accept
// must precede the catch-all drop for its direction.
func guardRules(c GuardConfig) []guardRule {
	guestIn, guestOut := termIfname("iifname", c.Guest), termIfname("oifname", c.Guest)
	upIn, upOut := termIfname("iifname", c.Uplink), termIfname("oifname", c.Uplink)
	toGateway := guardTerm{text: "ip daddr " + c.GatewayV4.String(), expr: jmatch("==", jpayload("ip", "daddr"), c.GatewayV4.String())}
	nfproto := guardTerm{text: "meta nfproto ipv4", expr: jmatch("==", jmeta("nfproto"), "ipv4")}
	toGrantedDst := guardTerm{text: "ip daddr @" + SetGrantedDst, expr: jmatch("==", jpayload("ip", "daddr"), "@"+SetGrantedDst)}
	reply := guardTerm{text: "ct direction reply", expr: jmatch("==", map[string]any{"ct": map[string]any{"key": "direction"}}, "reply")}
	established := guardTerm{
		text: "ct state established,related",
		expr: jmatch("in", map[string]any{"ct": map[string]any{"key": "state"}}, []any{"established", "related"}),
	}
	return []guardRule{
		{chainInput, "guest-dhcp", []guardTerm{guestIn, nfproto, termPort("udp", "sport", 68), termPort("udp", "dport", 67)}, "accept"},
		{chainInput, "guest-dns", []guardTerm{guestIn, toGateway, termSourcePair(SetBound), termPort("udp", "dport", c.DNSPort)}, "accept"},
		{chainInput, "guest-portal", []guardTerm{guestIn, toGateway, termSourcePair(SetBound), termPort("tcp", "dport", c.PortalPort)}, "accept"},
		{chainInput, "guest-input", []guardTerm{guestIn}, "drop"},
		{chainForward, "guest-protected", []guardTerm{guestIn, termProtected(c.Protected)}, "drop"},
		{chainForward, "grant-egress", []guardTerm{guestIn, upOut, termSourcePair(SetGranted)}, "accept"},
		{chainForward, "guest-egress", []guardTerm{guestIn}, "drop"},
		{chainForward, "grant-ingress", []guardTerm{upIn, guestOut, toGrantedDst, reply, established}, "accept"},
		{chainForward, "guest-ingress", []guardTerm{guestOut}, "drop"},
	}
}

// RenderGuardBootstrap renders the one-time guard installation batch. It
// begins with "create table", so the kernel rejects the whole transaction if
// the table already exists; it never deletes, flushes or merges into an
// existing (possibly dormant) table.
func RenderGuardBootstrap(c GuardConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("create table inet " + GuardTable + "\n")
	b.WriteString("table inet " + GuardTable + " {\n")
	for _, s := range guardSets {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tsize %d\n\t\tflags timeout\n\t}\n", s.name, s.typeText, SetSize)
	}
	rules := guardRules(c)
	for _, ch := range guardChains {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority %d; policy accept;\n", ch.name, ch.hook, guardPriority)
		for _, r := range rules {
			if r.chain == ch.name {
				b.WriteString("\t\t" + r.text() + "\n")
			}
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}
