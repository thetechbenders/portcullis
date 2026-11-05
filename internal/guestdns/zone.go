package guestdns

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
)

// ErrZone wraps every zone validation failure.
var ErrZone = errors.New("invalid guest DNS zone")

const (
	// MaxRecords bounds the static zone. The responder is a lookup table
	// for a handful of portal, probe and demo names, not a general server.
	MaxRecords = 64
	// DefaultTTL is deliberately short: guests should not cache the
	// portal's answers far beyond their visit, and a changed zone (for
	// example after a portal restart) converges quickly.
	DefaultTTL = 10 * time.Second
	// MaxTTL bounds operator-supplied TTLs.
	MaxTTL = time.Hour

	maxNameBytes = 253 // presentation form; the wire form is then <= 255
)

// dnsLabel mirrors the configuration's hostname rule: lowercase LDH labels.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Zone is the complete static data the responder serves.
type Zone struct {
	// Records maps lowercase fully qualified names, without a trailing dot,
	// to the single IPv4 address answered for an A query. Matching is exact:
	// a record does not cover any subdomain.
	Records map[string]netip.Addr
	// TTL is the answer TTL; it must be whole seconds in [1s, MaxTTL].
	TTL time.Duration

	// conflicts records names ZoneFrom saw with two different addresses.
	// A validated configuration never produces one; if it ever does, the
	// zone is ambiguous and NewResponder refuses it instead of picking one.
	conflicts []string
}

// ZoneFrom builds the guest zone from a validated configuration: every
// portal hostname and every captive-probe hostname answers with the
// gateway's guest address, plus the configured static dns_records. A nil
// configuration yields an empty zone, which NewResponder rejects.
func ZoneFrom(c *config.Config) Zone {
	z := Zone{Records: map[string]netip.Addr{}, TTL: DefaultTTL}
	if c == nil {
		return z
	}
	add := func(name string, addr netip.Addr) {
		if prev, dup := z.Records[name]; dup && prev != addr {
			z.conflicts = append(z.conflicts, name)
		}
		z.Records[name] = addr
	}
	for _, name := range c.PortalHostnames {
		add(name, c.GatewayV4)
	}
	for _, name := range c.ProbeHostnames {
		add(name, c.GatewayV4)
	}
	for _, name := range slices.Sorted(maps.Keys(c.DNSRecords)) {
		add(name, c.DNSRecords[name])
	}
	return z
}

// validName accepts the lowercase, dot-separated LDH names the
// configuration accepts. Anything else could never be matched by the
// case-folded lookup in Respond and is refused at construction.
func validName(name string) bool {
	if len(name) == 0 || len(name) > maxNameBytes {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// validRecordAddr accepts only addresses that make sense as a unicast
// destination for a guest. IPv4-mapped IPv6 is rejected: guests receive no
// IPv6 service and the zone holds A data only.
func validRecordAddr(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && a != limitedBroadcast
}

func (z Zone) validate() (map[string][4]byte, uint32, error) {
	if len(z.conflicts) > 0 {
		return nil, 0, fmt.Errorf("%w: name %q is configured with more than one address", ErrZone, z.conflicts[0])
	}
	if len(z.Records) == 0 || len(z.Records) > MaxRecords {
		return nil, 0, fmt.Errorf("%w: zone must hold 1-%d records, has %d", ErrZone, MaxRecords, len(z.Records))
	}
	if z.TTL < time.Second || z.TTL > MaxTTL || z.TTL%time.Second != 0 {
		return nil, 0, fmt.Errorf("%w: TTL must be whole seconds between 1s and %s", ErrZone, MaxTTL)
	}
	records := make(map[string][4]byte, len(z.Records))
	for _, name := range slices.Sorted(maps.Keys(z.Records)) {
		addr := z.Records[name]
		if !validName(name) {
			return nil, 0, fmt.Errorf("%w: name %q must be a lowercase multi-label hostname without a trailing dot", ErrZone, name)
		}
		if !validRecordAddr(addr) {
			return nil, 0, fmt.Errorf("%w: name %q must map to a unicast IPv4 address", ErrZone, name)
		}
		records[name] = addr.As4()
	}
	return records, uint32(z.TTL / time.Second), nil
}
