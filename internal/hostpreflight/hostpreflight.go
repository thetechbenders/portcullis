// Package hostpreflight provides read-only Linux host inventory and a deliberately
// non-authorizing assessment for prospective physical Portcullis deployment.
//
// No result from this package authorizes interface activation, guard bootstrap,
// system service installation or changes to the host network configuration.
package hostpreflight

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1

type Interface struct {
	Name          string   `json:"name"`
	Index         int      `json:"index"`
	MAC           string   `json:"mac,omitempty"`
	SysfsPath     string   `json:"sysfs_path,omitempty"`
	Driver        string   `json:"driver,omitempty"`
	Master        string   `json:"master,omitempty"`
	Uppers        []string `json:"uppers"`
	Addresses     []string `json:"addresses"`
	Up            bool     `json:"up"`
	Loopback      bool     `json:"loopback"`
	OperState     string   `json:"oper_state,omitempty"`
	IPv6Disabled  *bool    `json:"ipv6_disabled,omitempty"`
	AcceptRA      *int     `json:"accept_ra,omitempty"`
	MACAssignType *int     `json:"mac_assign_type,omitempty"`
}

type Route struct {
	Family      string `json:"family"`
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Default     bool   `json:"default"`
}

type Snapshot struct {
	BootID         string      `json:"boot_id,omitempty"`
	ObservedAt     string      `json:"observed_at"`
	IPv4Forwarding *bool       `json:"ipv4_forwarding,omitempty"`
	IPv6Forwarding *bool       `json:"ipv6_forwarding,omitempty"`
	Routes         []Route     `json:"routes"`
	Hostname       string      `json:"hostname,omitempty"`
	OS             string      `json:"os"`
	Arch           string      `json:"arch"`
	Kernel         string      `json:"kernel,omitempty"`
	Interfaces     []Interface `json:"interfaces"`
	DefaultRoutes  []Route     `json:"default_routes"`
	InventoryError []string    `json:"inventory_errors"`
}

// Selection is an *expected* topology supplied by an operator. No device is
// automatically selected from a default route or interface enumeration.
type Selection struct {
	Guest                 string `json:"guest,omitempty"`
	Uplink                string `json:"uplink,omitempty"`
	Management            string `json:"management,omitempty"`
	PinnedGuestMAC        string `json:"pinned_guest_mac,omitempty"`
	PinnedGuestSysfs      string `json:"pinned_guest_sysfs,omitempty"`
	PinnedUplinkMAC       string `json:"pinned_uplink_mac,omitempty"`
	PinnedUplinkSysfs     string `json:"pinned_uplink_sysfs,omitempty"`
	PinnedManagementMAC   string `json:"pinned_management_mac,omitempty"`
	PinnedManagementSysfs string `json:"pinned_management_sysfs,omitempty"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	BootID        string    `json:"boot_id,omitempty"`
	ObservedAt    string    `json:"observed_at"`
	PlanSHA256    string    `json:"plan_sha256"`
	Selection     Selection `json:"selection"`
	Hazards       []Finding `json:"hazards"`
	NotAssessed   []string  `json:"not_assessed"`
}

// Collect inspects only kernel-exposed files and the standard library's
// interface enumeration. It runs no shell, external program or privileged call.
func Collect() Snapshot {
	s := Snapshot{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		Interfaces: []Interface{}, DefaultRoutes: []Route{}, Routes: []Route{},
		ObservedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		InventoryError: []string{},
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		s.BootID = strings.TrimSpace(string(b))
	} else {
		s.InventoryError = append(s.InventoryError, "boot id: "+err.Error())
	}
	s.IPv4Forwarding = readBoolSysctl("/proc/sys/net/ipv4/ip_forward", &s.InventoryError)
	s.IPv6Forwarding = readBoolSysctl("/proc/sys/net/ipv6/conf/all/forwarding", &s.InventoryError)
	if name, err := os.Hostname(); err == nil {
		s.Hostname = name
	} else {
		s.InventoryError = append(s.InventoryError, "hostname: "+err.Error())
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	} else {
		s.InventoryError = append(s.InventoryError, "kernel release: "+err.Error())
	}
	ifs, err := net.Interfaces()
	if err != nil {
		s.InventoryError = append(s.InventoryError, "interface enumeration: "+err.Error())
	} else {
		for _, ni := range ifs {
			item := Interface{
				Name: ni.Name, Index: ni.Index, MAC: ni.HardwareAddr.String(),
				Up: ni.Flags&net.FlagUp != 0, Loopback: ni.Flags&net.FlagLoopback != 0,
				Uppers: []string{}, Addresses: []string{},
			}
			base := filepath.Join("/sys/class/net", ni.Name)
			if path, err := filepath.EvalSymlinks(filepath.Join(base, "device")); err == nil {
				item.SysfsPath = path
			} else if path, err := filepath.EvalSymlinks(base); err == nil {
				item.SysfsPath = path
			}
			item.IPv6Disabled = readBoolSysctl(filepath.Join("/proc/sys/net/ipv6/conf", ni.Name, "disable_ipv6"), &s.InventoryError)
			item.AcceptRA = readIntSysctl(filepath.Join("/proc/sys/net/ipv6/conf", ni.Name, "accept_ra"), &s.InventoryError)
			item.MACAssignType = readIntSysctl(filepath.Join(base, "addr_assign_type"), &s.InventoryError)
			if path, err := filepath.EvalSymlinks(filepath.Join(base, "device/driver")); err == nil {
				item.Driver = filepath.Base(path)
			}
			if path, err := filepath.EvalSymlinks(filepath.Join(base, "master")); err == nil {
				item.Master = filepath.Base(path)
			}
			if entries, err := os.ReadDir(base); err == nil {
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "upper_") {
						item.Uppers = append(item.Uppers, strings.TrimPrefix(entry.Name(), "upper_"))
					}
				}
				sort.Strings(item.Uppers)
			}
			if b, err := os.ReadFile(filepath.Join(base, "operstate")); err == nil {
				item.OperState = strings.TrimSpace(string(b))
			}
			if b, err := os.ReadFile(filepath.Join(base, "ifindex")); err == nil {
				if sysidx, err := strconv.Atoi(strings.TrimSpace(string(b))); err != nil || sysidx != ni.Index {
					s.InventoryError = append(s.InventoryError, "interface identity changed during collection: "+ni.Name)
				}
			} else {
				s.InventoryError = append(s.InventoryError, "interface ifindex unavailable: "+ni.Name)
			}
			if addrs, err := ni.Addrs(); err != nil {
				s.InventoryError = append(s.InventoryError, fmt.Sprintf("addresses for %q: %v", ni.Name, err))
			} else {
				for _, a := range addrs {
					item.Addresses = append(item.Addresses, a.String())
				}
				sort.Strings(item.Addresses)
			}
			s.Interfaces = append(s.Interfaces, item)
		}
		sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Name < s.Interfaces[j].Name })
	}
	for _, file := range []struct{ path, family string }{
		{"/proc/net/route", "ipv4"},
		{"/proc/net/ipv6_route", "ipv6"},
	} {
		lines, err := readBoundedLines(file.path, 256<<10)
		if err != nil {
			s.InventoryError = append(s.InventoryError, "routes "+file.family+": "+err.Error())
			continue
		}
		routes, err := ParseProcRoutes(file.family, lines)
		if err != nil {
			s.InventoryError = append(s.InventoryError, "routes "+file.family+": "+err.Error())
			continue
		}
		s.Routes = append(s.Routes, routes...)
		for _, route := range routes {
			if route.Default {
				s.DefaultRoutes = append(s.DefaultRoutes, route)
			}
		}
	}
	sort.Slice(s.Routes, func(i, j int) bool {
		a, b := s.Routes[i], s.Routes[j]
		if a.Family == b.Family {
			if a.Interface == b.Interface {
				return a.Destination < b.Destination
			}
			return a.Interface < b.Interface
		}
		return a.Family < b.Family
	})
	sort.Slice(s.DefaultRoutes, func(i, j int) bool {
		a, b := s.DefaultRoutes[i], s.DefaultRoutes[j]
		if a.Family == b.Family {
			return a.Interface < b.Interface
		}
		return a.Family < b.Family
	})
	return s
}

func readBoundedLines(path string, limit int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte read limit", limit)
	}
	out := []string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// Evaluate reports observed hazards separately from things this passive scan
// cannot assess. A zero-hazard check is NOT a grant of deployment authority.
func Evaluate(s Snapshot, sel Selection) Report {
	data, _ := json.Marshal(sel)
	digest := sha256.Sum256(data)
	r := Report{
		SchemaVersion: SchemaVersion, BootID: s.BootID, ObservedAt: s.ObservedAt,
		PlanSHA256: fmt.Sprintf("%x", digest), Selection: sel,
		Hazards: []Finding{}, NotAssessed: []string{
			"IPv4 policy rules and non-main routing tables are not observed by procfs",
			"NetworkManager/systemd-networkd and other interface ownership is unverified",
			"nftables guard, legacy firewall, tc/XDP and bypass paths are not attested",
			"independent guest exposure gate and physical recovery are unverified",
			"reboot, SIGKILL, packet and physical acceptance have not run",
		},
	}
	add := func(code, detail string) {
		r.Hazards = append(r.Hazards, Finding{Code: code, Severity: "hazard", Detail: detail})
	}
	for _, err := range s.InventoryError {
		add("inventory_incomplete", err)
	}
	if s.OS != "linux" {
		add("unsupported_os", "Linux host evidence is required")
	}
	if s.Arch != "arm64" {
		add("unverified_target_arch", "target Pi profile expects arm64")
	}
	if sel.Guest == "" || sel.Uplink == "" || sel.Management == "" {
		add("interfaces_not_selected", "guest, uplink and management must all be explicitly selected")
	}
	if sel.Guest != "" && (sel.Guest == sel.Uplink || sel.Guest == sel.Management) ||
		sel.Uplink != "" && sel.Uplink == sel.Management {
		add("overlapping_roles", "guest, uplink and management interfaces must be distinct")
	}
	byName := map[string]Interface{}
	for _, nic := range s.Interfaces {
		byName[nic.Name] = nic
	}
	for _, candidate := range []struct{ role, name string }{
		{"guest", sel.Guest},
		{"uplink", sel.Uplink},
		{"management", sel.Management},
	} {
		if candidate.name != "" {
			if _, found := byName[candidate.name]; !found {
				add("interface_missing", candidate.role+" interface "+candidate.name+" does not exist")
			}
		}
	}
	if sel.Guest != "" {
		if guest, ok := byName[sel.Guest]; ok {
			if guest.Loopback || guest.Up {
				add("guest_exposed", "guest interface must not be loopback or administratively UP during initial preflight")
			}
			if len(guest.Addresses) > 0 {
				add("guest_has_addresses", "guest interface already has an IP address; do not adopt it")
			}
			if guest.Master != "" || len(guest.Uppers) > 0 {
				add("guest_topology_conflict", "guest has a master or upper device; a bypass may exist")
			}
			if guest.MAC == "" || sel.PinnedGuestMAC == "" {
				add("guest_mac_unpinned", "a nonempty physical guest MAC and operator pin are required")
			} else if !strings.EqualFold(guest.MAC, sel.PinnedGuestMAC) {
				add("guest_mac_mismatch", "observed guest MAC differs from operator-pinned MAC")
			}
			if strings.HasPrefix(guest.SysfsPath, "/sys/devices/virtual/") {
				add("virtual_guest_interface", "guest device is a virtual interface, not an operator-pinned physical NIC")
			}
			if guest.MACAssignType == nil || *guest.MACAssignType != 0 {
				add("guest_mac_not_permanent", "guest MAC is not confirmed as a permanent hardware assignment")
			}
			if guest.IPv6Disabled == nil || !*guest.IPv6Disabled {
				add("guest_ipv6_enabled", "guest IPv6 disable state is not confirmed as disabled")
			}
			if guest.AcceptRA == nil || *guest.AcceptRA != 0 {
				add("guest_accept_ra", "guest IPv6 router advertisements are not confirmed disabled")
			}
			if guest.SysfsPath == "" || sel.PinnedGuestSysfs == "" {
				add("guest_path_unpinned", "guest sysfs identity is missing or not pinned")
			} else if guest.SysfsPath != sel.PinnedGuestSysfs {
				add("guest_path_mismatch", "guest sysfs identity differs from operator-pinned path")
			}
		}
	}
	for _, role := range []struct {
		name, label, pinMAC, pinPath string
	}{
		{sel.Uplink, "uplink", sel.PinnedUplinkMAC, sel.PinnedUplinkSysfs},
		{sel.Management, "management", sel.PinnedManagementMAC, sel.PinnedManagementSysfs},
	} {
		if nic, ok := byName[role.name]; ok {
			if nic.MAC == "" || role.pinMAC == "" || !strings.EqualFold(nic.MAC, role.pinMAC) {
				add(role.label+"_mac_mismatch", "physical "+role.label+" current MAC is missing or differs from its pin")
			}
			if nic.SysfsPath == "" || role.pinPath == "" || nic.SysfsPath != role.pinPath {
				add(role.label+"_path_mismatch", "physical "+role.label+" parent device identity differs from its pin")
			}
			if strings.HasPrefix(nic.SysfsPath, "/sys/devices/virtual/") {
				add(role.label+"_virtual_interface", role.label+" role uses a virtual rather than pinned physical interface")
			}
		}
	}
	if sel.Management != "" {
		if mgmt, ok := byName[sel.Management]; ok {
			if !mgmt.Up || len(mgmt.Addresses) == 0 {
				add("management_inactive", "management interface is not up with an address")
			}
		}
	}
	for _, route := range s.Routes {
		if sel.Guest != "" && route.Interface == sel.Guest {
			add("guest_route", "a "+route.Family+" route is configured through the candidate guest interface")
		}
		if route.Default && sel.Uplink != "" && route.Interface != sel.Uplink {
			add("default_route_not_uplink", "a "+route.Family+" default route uses "+route.Interface+" rather than the nominated uplink")
		}
	}
	// Legacy snapshots/tests can provide default routes separately.
	if len(s.Routes) == 0 {
		for _, route := range s.DefaultRoutes {
			if sel.Guest != "" && route.Interface == sel.Guest {
				add("guest_route", "guest interface has a default route")
			}
			if sel.Uplink != "" && route.Interface != sel.Uplink {
				add("default_route_not_uplink", "default route does not use uplink")
			}
		}
	}
	if s.IPv4Forwarding == nil || *s.IPv4Forwarding {
		add("ipv4_forwarding_active_or_unknown", "IPv4 forwarding must be verified disabled before initial exposure")
	}
	if s.IPv6Forwarding == nil || *s.IPv6Forwarding {
		add("ipv6_forwarding_active_or_unknown", "IPv6 forwarding must be verified disabled")
	}
	management, haveManagement := byName[sel.Management]
	uplink, haveUplink := byName[sel.Uplink]
	if haveManagement && haveUplink {
		for _, left := range management.Addresses {
			a, err := netip.ParsePrefix(left)
			if err != nil {
				add("invalid_management_address", "management address cannot be parsed")
				continue
			}
			for _, right := range uplink.Addresses {
				b, err := netip.ParsePrefix(right)
				if err != nil {
					add("invalid_uplink_address", "uplink address cannot be parsed")
					continue
				}
				if a.Addr().Is4() == b.Addr().Is4() && a.Overlaps(b) {
					add("management_uplink_overlap", "management and uplink address prefixes overlap")
				}
			}
		}
	}
	return r
}

// Sysctl reads are passive; unavailable kernel state remains unknown.
func readIntSysctl(path string, problems *[]string) *int {
	b, err := os.ReadFile(path)
	if err != nil {
		*problems = append(*problems, "cannot read "+path+": "+err.Error())
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		*problems = append(*problems, "invalid sysctl "+path)
		return nil
	}
	return &n
}

func readBoolSysctl(path string, problems *[]string) *bool {
	n := readIntSysctl(path, problems)
	if n == nil {
		return nil
	}
	if *n != 0 && *n != 1 {
		*problems = append(*problems, "unexpected boolean sysctl "+path)
		return nil
	}
	v := *n == 1
	return &v
}
