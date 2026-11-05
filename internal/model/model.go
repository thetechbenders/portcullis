// Package model defines the small, comparable data types shared by the
// Portcullis controller, DHCP server, kernel policy renderers and portal.
// It performs no I/O and makes no authorization decisions.
package model

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrMAC rejects anything other than a non-zero unicast 48-bit address.
var ErrMAC = errors.New("MAC address must be a non-zero unicast 48-bit Ethernet address")

// MAC is a comparable 48-bit Ethernet address. A MAC is attachment
// evidence only in combination with kernel ether-source enforcement; it is
// trivially forgeable by any station that can clone another's address.
type MAC [6]byte

// ParseMAC accepts the colon, hyphen or dot forms understood by
// net.ParseMAC, restricted to non-zero unicast 48-bit addresses.
func ParseMAC(s string) (MAC, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return MAC{}, ErrMAC
	}
	return MACFromBytes(hw)
}

// MACFromBytes validates a raw 6-byte hardware address.
func MACFromBytes(b []byte) (MAC, error) {
	var m MAC
	if len(b) != len(m) {
		return MAC{}, ErrMAC
	}
	copy(m[:], b)
	if m.IsZero() || m[0]&1 != 0 {
		return MAC{}, ErrMAC
	}
	return m, nil
}

// String returns the canonical lowercase colon form used in nft batches.
func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// IsZero reports whether m is the all-zero address.
func (m MAC) IsZero() bool { return m == MAC{} }

// Hint returns a guest-facing fragment that helps a person recognize their
// own device without publishing the full address.
func (m MAC) Hint() string { return fmt.Sprintf("…:%02x:%02x", m[4], m[5]) }

// Binding is an IPv4 assignment issued by the Portcullis DHCP server itself
// on the guest interface. The MAC is the client's DHCP chaddr: a claim that
// becomes meaningful only because the kernel guard admits guest packets
// solely when their IPv4 source and Ethernet source match a live binding.
type Binding struct {
	MAC     MAC
	Addr    netip.Addr
	Expires time.Time
}

// Neighbor is one kernel IPv4 neighbour (ARP) table entry, observed by the
// gateway rather than reported by the client.
type Neighbor struct {
	Addr      netip.Addr
	MAC       MAC
	Device    string
	Complete  bool // ATF_COM: the hardware address is resolved
	Permanent bool // ATF_PERM: statically configured
}

// Element is one kernel set element observed through nft JSON.
type Element struct {
	Addr netip.Addr
	// MAC is zero for address-only sets such as granted_dst_v4.
	MAC MAC
	// Timeout is the element's configured kernel timeout. Zero means the
	// element has NO timeout and therefore never expires in the kernel.
	Timeout time.Duration
	// Expires is the remaining lifetime reported by the kernel.
	Expires time.Duration
}

// Counter is a labelled nft rule counter.
type Counter struct {
	Rule    string
	Packets uint64
	Bytes   uint64
}

// KernelState is an attested snapshot of the persistent Portcullis guard.
type KernelState struct {
	Bound      []Element
	Granted    []Element
	GrantedDst []Element
	Counters   []Counter
}
