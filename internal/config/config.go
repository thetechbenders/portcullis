// Package config loads the single Portcullis deployment description shared by
// portcullisd, the portal and operator tooling. Decoding is strict: unknown
// fields, trailing data, unsafe interface names, wildcard addresses and
// inconsistent topology are rejected rather than repaired.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid portcullis configuration")

const (
	maxFileBytes   = 64 << 10
	maxPoolSize    = 1000 // the kernel sets are sized 1024
	maxHostnames   = 8
	maxDNSRecords  = 16
	maxProtected   = 64
	maxGrantLength = 15 * time.Minute
)

var (
	safeInterface = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)
	dnsLabel      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// DefaultProtectedV4 lists destinations guests must never reach, even with
// a grant: unspecified, private, CGNAT, loopback, link-local, IETF protocol
// assignments, multicast and reserved/broadcast space.
var DefaultProtectedV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

// DefaultProbeHostnames are operating-system captive portal probes that the
// guest DNS answers with the portal address. HTTPS is never intercepted.
var DefaultProbeHostnames = []string{
	"captive.apple.com", "connectivitycheck.gstatic.com", "clients3.google.com",
	"connectivitycheck.android.com", "www.msftconnecttest.com",
	"detectportal.firefox.com", "nmcheck.gnome.org",
}

// File is the on-disk JSON schema.
type File struct {
	GuestInterface        string            `json:"guest_interface"`
	UplinkInterface       string            `json:"uplink_interface"`
	GatewayV4             string            `json:"gateway_v4"`
	GuestSubnetV4         string            `json:"guest_subnet_v4"`
	DHCPPoolStart         string            `json:"dhcp_pool_start"`
	DHCPPoolEnd           string            `json:"dhcp_pool_end"`
	DHCPLeaseSeconds      int               `json:"dhcp_lease_seconds"`
	PortalPort            int               `json:"portal_port"`
	DNSPort               int               `json:"dns_port"`
	PortalHostnames       []string          `json:"portal_hostnames"`
	ProbeHostnames        []string          `json:"probe_hostnames,omitempty"`
	DNSRecords            map[string]string `json:"dns_records,omitempty"`
	ProtectedV4           []string          `json:"protected_v4,omitempty"`
	GrantDefaultSeconds   int               `json:"grant_default_seconds"`
	GrantMaxSeconds       int               `json:"grant_max_seconds"`
	RevokeCooldownSeconds int               `json:"revoke_cooldown_seconds"`
	GuestSocket           string            `json:"guest_socket"`
	OperatorSocket        string            `json:"operator_socket"`
	PortalUID             int               `json:"portal_uid"`
	NFTPath               string            `json:"nft_path"`
	ConntrackPath         string            `json:"conntrack_path"`
	IPPath                string            `json:"ip_path"`
	FailsafeLinkDown      bool              `json:"failsafe_link_down"`
}

// Config is the validated, typed configuration.
type Config struct {
	GuestInterface  string
	UplinkInterface string
	GatewayV4       netip.Addr
	GuestSubnetV4   netip.Prefix
	PoolStart       netip.Addr
	PoolEnd         netip.Addr
	DHCPLease       time.Duration
	PortalPort      uint16
	DNSPort         uint16
	// PortalHostnames are the only Host header names the portal serves as
	// itself; the first is canonical.
	PortalHostnames []string
	ProbeHostnames  []string
	// DNSRecords are additional static A records (for example the demo
	// destination). Keys are lowercase names without a trailing dot.
	DNSRecords     map[string]netip.Addr
	ProtectedV4    []netip.Prefix
	GrantDefault   time.Duration
	GrantMax       time.Duration
	RevokeCooldown time.Duration
	GuestSocket    string
	OperatorSocket string
	PortalUID      uint32
	NFTPath        string
	ConntrackPath  string
	IPPath         string
	// FailsafeLinkDown sets the guest interface administratively down when
	// the guard cannot be attested at runtime.
	FailsafeLinkDown bool
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse strictly decodes and validates configuration JSON.
func Parse(data []byte) (*Config, error) {
	if len(data) == 0 || len(data) > maxFileBytes {
		return nil, fmt.Errorf("%w: missing or oversized file", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing content", ErrInvalid)
	}
	return f.Validate()
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate converts the file schema into a typed Config.
func (f File) Validate() (*Config, error) {
	c := &Config{FailsafeLinkDown: f.FailsafeLinkDown}
	if !safeInterface.MatchString(f.GuestInterface) || !safeInterface.MatchString(f.UplinkInterface) {
		return nil, invalid("interface names must be 1-15 safe ASCII bytes")
	}
	if f.GuestInterface == f.UplinkInterface {
		return nil, invalid("guest and uplink interfaces must differ")
	}
	c.GuestInterface, c.UplinkInterface = f.GuestInterface, f.UplinkInterface

	var err error
	if c.GuestSubnetV4, err = netip.ParsePrefix(f.GuestSubnetV4); err != nil || !c.GuestSubnetV4.Addr().Is4() ||
		c.GuestSubnetV4 != c.GuestSubnetV4.Masked() || c.GuestSubnetV4.Bits() < 16 || c.GuestSubnetV4.Bits() > 29 {
		return nil, invalid("guest_subnet_v4 must be a canonical IPv4 prefix between /16 and /29")
	}
	network := c.GuestSubnetV4.Addr()
	broadcast := lastAddr(c.GuestSubnetV4)
	inner := func(a netip.Addr) bool {
		return a.Is4() && c.GuestSubnetV4.Contains(a) && a != network && a != broadcast
	}
	if c.GatewayV4, err = netip.ParseAddr(f.GatewayV4); err != nil || !inner(c.GatewayV4) {
		return nil, invalid("gateway_v4 must be a host address inside guest_subnet_v4")
	}
	if c.PoolStart, err = netip.ParseAddr(f.DHCPPoolStart); err != nil || !inner(c.PoolStart) {
		return nil, invalid("dhcp_pool_start must be a host address inside guest_subnet_v4")
	}
	if c.PoolEnd, err = netip.ParseAddr(f.DHCPPoolEnd); err != nil || !inner(c.PoolEnd) {
		return nil, invalid("dhcp_pool_end must be a host address inside guest_subnet_v4")
	}
	if c.PoolEnd.Less(c.PoolStart) {
		return nil, invalid("dhcp pool end precedes start")
	}
	if !c.GatewayV4.Less(c.PoolStart) && !c.PoolEnd.Less(c.GatewayV4) {
		return nil, invalid("gateway_v4 must not be inside the DHCP pool")
	}
	if size := poolSize(c.PoolStart, c.PoolEnd); size > maxPoolSize {
		return nil, invalid("dhcp pool has %d addresses; maximum is %d", size, maxPoolSize)
	}
	if f.DHCPLeaseSeconds < 60 || f.DHCPLeaseSeconds > 7200 {
		return nil, invalid("dhcp_lease_seconds must be between 60 and 7200")
	}
	c.DHCPLease = time.Duration(f.DHCPLeaseSeconds) * time.Second

	if f.PortalPort < 1 || f.PortalPort > 65535 || f.DNSPort < 1 || f.DNSPort > 65535 {
		return nil, invalid("portal_port and dns_port must be valid TCP/UDP ports")
	}
	c.PortalPort, c.DNSPort = uint16(f.PortalPort), uint16(f.DNSPort)

	if len(f.PortalHostnames) == 0 || len(f.PortalHostnames) > maxHostnames {
		return nil, invalid("portal_hostnames must list 1-%d names", maxHostnames)
	}
	seen := map[string]bool{}
	for _, name := range f.PortalHostnames {
		if !validHostname(name) || seen[name] {
			return nil, invalid("invalid or duplicate portal hostname %q", name)
		}
		seen[name] = true
		c.PortalHostnames = append(c.PortalHostnames, name)
	}
	probes := f.ProbeHostnames
	if probes == nil {
		probes = DefaultProbeHostnames
	}
	if len(probes) > 2*maxHostnames {
		return nil, invalid("too many probe hostnames")
	}
	for _, name := range probes {
		if !validHostname(name) || seen[name] {
			return nil, invalid("invalid or duplicate probe hostname %q", name)
		}
		seen[name] = true
		c.ProbeHostnames = append(c.ProbeHostnames, name)
	}
	if len(f.DNSRecords) > maxDNSRecords {
		return nil, invalid("at most %d dns_records", maxDNSRecords)
	}
	c.DNSRecords = make(map[string]netip.Addr, len(f.DNSRecords))
	for name, value := range f.DNSRecords {
		addr, err := netip.ParseAddr(value)
		if !validHostname(name) || seen[name] || err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, invalid("dns_records entry %q must map a unique hostname to a unicast IPv4 address", name)
		}
		seen[name] = true
		c.DNSRecords[name] = addr
	}

	protected := f.ProtectedV4
	if protected == nil {
		protected = DefaultProtectedV4
	}
	if len(protected) == 0 || len(protected) > maxProtected {
		return nil, invalid("protected_v4 must list 1-%d prefixes", maxProtected)
	}
	for _, text := range protected {
		p, err := netip.ParsePrefix(text)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, invalid("protected_v4 entry %q must be a canonical IPv4 prefix", text)
		}
		for _, q := range c.ProtectedV4 {
			if p.Overlaps(q) {
				return nil, invalid("protected_v4 prefixes %s and %s overlap", p, q)
			}
		}
		c.ProtectedV4 = append(c.ProtectedV4, p)
	}
	for name, addr := range c.DNSRecords {
		for _, p := range c.ProtectedV4 {
			if p.Contains(addr) {
				return nil, invalid("dns_records %q points into protected prefix %s", name, p)
			}
		}
	}

	if f.GrantMaxSeconds < 30 || time.Duration(f.GrantMaxSeconds)*time.Second > maxGrantLength {
		return nil, invalid("grant_max_seconds must be between 30 and %d", int(maxGrantLength/time.Second))
	}
	if f.GrantDefaultSeconds < 30 || f.GrantDefaultSeconds > f.GrantMaxSeconds {
		return nil, invalid("grant_default_seconds must be between 30 and grant_max_seconds")
	}
	if time.Duration(f.GrantMaxSeconds)*time.Second > c.DHCPLease {
		return nil, invalid("grant_max_seconds must not exceed dhcp_lease_seconds")
	}
	if f.RevokeCooldownSeconds < 0 || f.RevokeCooldownSeconds > 3600 {
		return nil, invalid("revoke_cooldown_seconds must be between 0 and 3600")
	}
	c.GrantDefault = time.Duration(f.GrantDefaultSeconds) * time.Second
	c.GrantMax = time.Duration(f.GrantMaxSeconds) * time.Second
	c.RevokeCooldown = time.Duration(f.RevokeCooldownSeconds) * time.Second

	for _, p := range []struct{ name, value string }{
		{"guest_socket", f.GuestSocket}, {"operator_socket", f.OperatorSocket},
		{"nft_path", f.NFTPath}, {"conntrack_path", f.ConntrackPath}, {"ip_path", f.IPPath},
	} {
		if !filepath.IsAbs(p.value) || filepath.Clean(p.value) != p.value || strings.ContainsAny(p.value, "\x00\n") {
			return nil, invalid("%s must be a clean absolute path", p.name)
		}
	}
	if f.GuestSocket == f.OperatorSocket {
		return nil, invalid("guest_socket and operator_socket must differ")
	}
	c.GuestSocket, c.OperatorSocket = f.GuestSocket, f.OperatorSocket
	c.NFTPath, c.ConntrackPath, c.IPPath = f.NFTPath, f.ConntrackPath, f.IPPath
	if f.PortalUID <= 0 || f.PortalUID > 1<<31-2 {
		return nil, invalid("portal_uid must be a non-root uid")
	}
	c.PortalUID = uint32(f.PortalUID)
	return c, nil
}

// PortalURL is the canonical plain-HTTP guest portal address.
func (c *Config) PortalURL() string {
	host := c.PortalHostnames[0]
	if c.PortalPort != 80 {
		return fmt.Sprintf("http://%s:%d/", host, c.PortalPort)
	}
	return "http://" + host + "/"
}

// PortalListen is the guest-facing portal listener. It is always the
// gateway's own guest address, never a wildcard.
func (c *Config) PortalListen() netip.AddrPort { return netip.AddrPortFrom(c.GatewayV4, c.PortalPort) }

// DNSListen is the guest-facing DNS listener on the gateway guest address.
func (c *Config) DNSListen() netip.AddrPort { return netip.AddrPortFrom(c.GatewayV4, c.DNSPort) }

// AllowedHosts are the Host header values the portal treats as itself.
func (c *Config) AllowedHosts() []string {
	hosts := slices.Clone(c.PortalHostnames)
	hosts = append(hosts, c.GatewayV4.String())
	return hosts
}

func validHostname(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.ToLower(name) != name || strings.HasSuffix(name, ".") {
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

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func poolSize(start, end netip.Addr) int {
	s, e := start.As4(), end.As4()
	sv := uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
	ev := uint32(e[0])<<24 | uint32(e[1])<<16 | uint32(e[2])<<8 | uint32(e[3])
	return int(ev-sv) + 1
}
