package hostpreflight

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

const (
	routeUp     = 0x1
	routeReject = 0x200
)

// ParseProcRoutes parses the kernel's procfs representations without mistaking
// reject/null IPv6 entries for usable defaults. It is NOT a complete dump of
// every IPv4 policy routing table or ip rule.
func ParseProcRoutes(family string, lines []string) ([]Route, error) {
	out := []Route{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || (family == "ipv4" && fields[0] == "Iface") {
			continue
		}
		switch family {
		case "ipv4":
			if len(fields) < 8 {
				return nil, fmt.Errorf("invalid IPv4 proc route: %q", line)
			}
			flags, err := strconv.ParseUint(fields[3], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv4 route flags: %w", err)
			}
			if flags&routeUp == 0 || flags&routeReject != 0 {
				continue
			}
			dst, err := parseIPv4ProcHex(fields[1])
			if err != nil {
				return nil, err
			}
			mask, err := strconv.ParseUint(fields[7], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv4 route mask: %w", err)
			}
			prefix := bits.OnesCount32(uint32(mask))
			network := netip.PrefixFrom(dst, prefix).Masked()
			out = append(out, Route{
				Family: "ipv4", Interface: fields[0],
				Destination: network.String(), Default: dst.IsUnspecified() && mask == 0,
			})
		case "ipv6":
			if len(fields) < 10 {
				return nil, fmt.Errorf("invalid IPv6 proc route: %q", line)
			}
			flags, err := strconv.ParseUint(fields[8], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv6 route flags: %w", err)
			}
			// Kernel-generated null/reject entries often target lo and look
			// like a ::/0 route unless the RTF_REJECT bit is considered.
			if flags&routeUp == 0 || flags&routeReject != 0 {
				continue
			}
			addr, err := hex.DecodeString(fields[0])
			if err != nil || len(addr) != 16 {
				return nil, fmt.Errorf("invalid IPv6 route destination %q", fields[0])
			}
			dest, ok := netip.AddrFromSlice(addr)
			if !ok {
				return nil, fmt.Errorf("invalid IPv6 route destination")
			}
			plen, err := strconv.ParseUint(fields[1], 16, 8)
			if err != nil || plen > 128 {
				return nil, fmt.Errorf("invalid IPv6 prefix length %q", fields[1])
			}
			network := netip.PrefixFrom(dest, int(plen)).Masked()
			out = append(out, Route{
				Family: "ipv6", Interface: fields[9],
				Destination: network.String(),
				Default:     dest.IsUnspecified() && plen == 0,
			})
		default:
			return nil, fmt.Errorf("unknown route family %q", family)
		}
	}
	return out, nil
}

func parseIPv4ProcHex(s string) (netip.Addr, error) {
	if len(s) != 8 {
		return netip.Addr{}, fmt.Errorf("invalid IPv4 proc address %q", s)
	}
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}), nil
}
