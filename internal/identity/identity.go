// Package identity cross-checks a DHCP binding against the neighbour (ARP)
// state the gateway kernel itself resolved on the guest interface.
//
// Limitations, stated rather than hidden: the ARP table reflects the last
// resolution, not the sender of any particular packet. It corroborates a
// binding but does not prove identity, and a station that clones both the
// MAC and IPv4 address of another station defeats it. Any guest can place an
// arbitrary sender hardware address into the table with an ARP request,
// which is why disagreement fails closed rather than being repaired.
package identity

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	// ErrBindingMismatch: the binding does not describe the observed address.
	ErrBindingMismatch = errors.New("binding does not match the observed address")
	// ErrNoNeighbor: no complete neighbour entry for the address on the interface.
	ErrNoNeighbor = errors.New("no resolved neighbour entry on the guest interface")
	// ErrWrongInterface: the address is known only on another device.
	ErrWrongInterface = errors.New("neighbour entry exists only on another interface")
	// ErrNeighborMismatch: the resolved hardware address differs from the binding.
	ErrNeighborMismatch = errors.New("neighbour hardware address differs from the DHCP binding")
	// ErrNeighborSource: the neighbour table could not be read (fail closed).
	ErrNeighborSource = errors.New("neighbour table unavailable")
	// ErrARPFormat wraps every /proc/net/arp parse failure.
	ErrARPFormat = errors.New("malformed /proc/net/arp content")
)

// DefaultARPPath is the kernel IPv4 neighbour table of the caller's netns.
const DefaultARPPath = "/proc/net/arp"

const (
	maxARPLines     = 8192
	maxARPLineBytes = 256
	maxARPBytes     = maxARPLines * (maxARPLineBytes + 1)

	hwEthernet = 0x1
	atfCom     = 0x2
	atfPerm    = 0x4
	atfPubl    = 0x8
)

var arpHeader = []string{"IP", "address", "HW", "type", "Flags", "HW", "address", "Mask", "Device"}

func formatErr(line int, what string) error {
	return fmt.Errorf("%w: line %d: %s", ErrARPFormat, line, what)
}

func parseHex(s string) (uint64, bool) {
	if !strings.HasPrefix(s, "0x") {
		return 0, false
	}
	v, err := strconv.ParseUint(s[2:], 16, 32)
	return v, err == nil
}

// ParseProcNetARP strictly parses /proc/net/arp. Only Ethernet rows are
// returned. Entries without ATF_COM (incomplete, failed, proxy) are returned
// with Complete=false and a zero MAC whatever hardware address is printed,
// because the kernel prints stale addresses for failed entries. A complete
// entry whose address is not a valid unicast MAC (guest-controllable) is
// returned with Complete=true and a zero MAC so corroboration reports a
// mismatch for that address instead of the whole table failing.
func ParseProcNetARP(r io.Reader) ([]model.Neighbor, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxARPLineBytes+1), maxARPLineBytes+1)
	var out []model.Neighbor
	line := 0
	for sc.Scan() {
		line++
		if line > maxARPLines {
			return nil, formatErr(line, "too many lines")
		}
		text := sc.Text()
		if len(text) > maxARPLineBytes {
			return nil, formatErr(line, "line too long")
		}
		f := strings.Fields(text)
		if line == 1 {
			if !slices.Equal(f, arpHeader) {
				return nil, formatErr(line, "unexpected header")
			}
			continue
		}
		if len(f) != 6 {
			return nil, formatErr(line, "wrong column count")
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil || !addr.Is4() {
			return nil, formatErr(line, "invalid IPv4 address")
		}
		hw, ok1 := parseHex(f[1])
		flags, ok2 := parseHex(f[2])
		if !ok1 || !ok2 {
			return nil, formatErr(line, "invalid hex field")
		}
		if f[4] != "*" || len(f[5]) > 15 {
			return nil, formatErr(line, "invalid mask or device")
		}
		if hw != hwEthernet {
			continue
		}
		raw, err := net.ParseMAC(f[3])
		if err != nil || len(raw) != 6 || len(f[3]) != 17 {
			return nil, formatErr(line, "invalid hardware address")
		}
		n := model.Neighbor{
			Addr:      addr,
			Device:    f[5],
			Complete:  flags&atfCom != 0 && flags&atfPubl == 0,
			Permanent: flags&atfPerm != 0,
		}
		if n.Complete {
			if mac, err := model.MACFromBytes(raw); err == nil {
				n.MAC = mac
			}
		}
		out = append(out, n)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrARPFormat, err)
	}
	if line == 0 {
		return nil, formatErr(0, "empty input")
	}
	return out, nil
}

// NeighborSource yields the kernel neighbour table.
type NeighborSource interface {
	Neighbors() ([]model.Neighbor, error)
}

// ProcARP reads a /proc/net/arp style file.
type ProcARP struct{ Path string }

// Neighbors reads and parses the table with a size bound.
func (p ProcARP) Neighbors() ([]model.Neighbor, error) {
	path := p.Path
	if path == "" {
		path = DefaultARPPath
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("neighbour table path must be clean and absolute")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxARPBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxARPBytes {
		return nil, fmt.Errorf("%w: table exceeds %d bytes", ErrARPFormat, maxARPBytes)
	}
	return ParseProcNetARP(bytes.NewReader(data))
}

// Corroborator checks bindings against neighbour state on one interface.
type Corroborator struct {
	Source    NeighborSource
	Interface string
}

// Corroborate returns nil only if b describes addr and the kernel holds a
// complete neighbour entry for addr on Interface carrying b.MAC, with no
// complete entry on Interface carrying any other address.
func (c Corroborator) Corroborate(addr netip.Addr, b model.Binding) error {
	if !addr.Is4() || b.Addr != addr {
		return ErrBindingMismatch
	}
	if _, err := model.MACFromBytes(b.MAC[:]); err != nil {
		return fmt.Errorf("%w: binding has no valid MAC", ErrBindingMismatch)
	}
	if c.Source == nil || c.Interface == "" {
		return fmt.Errorf("%w: corroborator not configured", ErrNeighborSource)
	}
	neighbors, err := c.Source.Neighbors()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNeighborSource, err)
	}
	onIface, elsewhere, matched := false, false, false
	for _, n := range neighbors {
		if n.Addr != addr {
			continue
		}
		if n.Device != c.Interface {
			elsewhere = true
			continue
		}
		onIface = true
		if n.Complete {
			if n.MAC != b.MAC {
				return ErrNeighborMismatch
			}
			matched = true
		}
	}
	switch {
	case matched:
		return nil
	case !onIface && elsewhere:
		return ErrWrongInterface
	}
	return ErrNoNeighbor
}
