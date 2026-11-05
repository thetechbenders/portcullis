package dhcp

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
)

// ErrInvalidConfig wraps every server configuration failure.
var ErrInvalidConfig = errors.New("invalid DHCP server configuration")

const (
	// maxPoolSize matches the kernel bound_v4 set size.
	maxPoolSize = 1024
	// maxLease matches the longest bound_v4 element timeout the kernel
	// renderer accepts, so every ACKed lease can be backed by evidence.
	maxLease = 2 * time.Hour

	defaultOfferTimeout      = 30 * time.Second
	defaultDeclineQuarantine = 10 * time.Minute
)

var safeInterface = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)

// Config describes the single directly attached guest segment served.
type Config struct {
	Interface          string
	ServerIP           netip.Addr
	Subnet             netip.Prefix
	PoolStart, PoolEnd netip.Addr
	Router, DNS        netip.Addr
	LeaseTime          time.Duration
	OfferTimeout       time.Duration
	DeclineQuarantine  time.Duration
	MaxBindings        int
}

// ConfigFrom derives the server configuration from the deployment config.
// The gateway is server identifier, router and DNS server.
func ConfigFrom(c *config.Config) Config {
	return Config{
		Interface:         c.GuestInterface,
		ServerIP:          c.GatewayV4,
		Subnet:            c.GuestSubnetV4,
		PoolStart:         c.PoolStart,
		PoolEnd:           c.PoolEnd,
		Router:            c.GatewayV4,
		DNS:               c.GatewayV4,
		LeaseTime:         c.DHCPLease,
		OfferTimeout:      defaultOfferTimeout,
		DeclineQuarantine: defaultDeclineQuarantine,
		MaxBindings:       poolSize(c.PoolStart, c.PoolEnd),
	}
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}

// Validate rejects any configuration that could hand out the server, network
// or broadcast address, overflow the kernel set, or issue a lease the kernel
// evidence cannot cover.
func (c Config) Validate() error {
	if !safeInterface.MatchString(c.Interface) {
		return invalid("interface name must be 1-15 safe ASCII bytes")
	}
	if !c.Subnet.IsValid() || !c.Subnet.Addr().Is4() || c.Subnet != c.Subnet.Masked() ||
		c.Subnet.Bits() < 8 || c.Subnet.Bits() > 30 {
		return invalid("subnet must be a canonical IPv4 prefix between /8 and /30")
	}
	network, broadcast := c.Subnet.Addr(), lastAddr(c.Subnet)
	host := func(a netip.Addr) bool {
		return a.Is4() && c.Subnet.Contains(a) && a != network && a != broadcast
	}
	if !host(c.ServerIP) {
		return invalid("server address must be a host address inside the subnet")
	}
	if !host(c.Router) {
		return invalid("router must be a host address inside the subnet")
	}
	if !c.DNS.Is4() || c.DNS.IsUnspecified() || c.DNS.IsMulticast() || c.DNS.IsLoopback() || c.DNS == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return invalid("DNS server must be a unicast IPv4 address")
	}
	if !host(c.PoolStart) || !host(c.PoolEnd) || c.PoolEnd.Less(c.PoolStart) {
		return invalid("pool must be an ordered range of host addresses inside the subnet")
	}
	inPool := func(a netip.Addr) bool { return !a.Less(c.PoolStart) && !c.PoolEnd.Less(a) }
	if inPool(c.ServerIP) || inPool(c.Router) || inPool(c.DNS) {
		return invalid("pool must exclude the server, router and DNS addresses")
	}
	size := poolSize(c.PoolStart, c.PoolEnd)
	if size > maxPoolSize {
		return invalid("pool has %d addresses; maximum is %d", size, maxPoolSize)
	}
	if c.LeaseTime < time.Minute || c.LeaseTime > maxLease || c.LeaseTime%time.Second != 0 {
		return invalid("lease time must be whole seconds between 60s and %s", maxLease)
	}
	if c.OfferTimeout < time.Second || c.OfferTimeout > 5*time.Minute {
		return invalid("offer timeout must be between 1s and 5m")
	}
	if c.DeclineQuarantine < time.Second || c.DeclineQuarantine > 24*time.Hour {
		return invalid("decline quarantine must be between 1s and 24h")
	}
	if c.MaxBindings < 1 || c.MaxBindings > size {
		return invalid("max bindings must be between 1 and the pool size")
	}
	return nil
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func lastAddr(p netip.Prefix) netip.Addr {
	return fromU32(u32(p.Addr()) | (uint32(1)<<(32-p.Bits()) - 1))
}

func poolSize(start, end netip.Addr) int {
	if !start.Is4() || !end.Is4() || end.Less(start) {
		return 0
	}
	return int(u32(end)-u32(start)) + 1
}
