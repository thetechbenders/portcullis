package config

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func labFile() File {
	return File{
		GuestInterface: "guest0", UplinkInterface: "uplink0",
		GatewayV4: "10.203.0.1", GuestSubnetV4: "10.203.0.0/24",
		DHCPPoolStart: "10.203.0.100", DHCPPoolEnd: "10.203.0.199", DHCPLeaseSeconds: 600,
		PortalPort: 80, DNSPort: 53,
		PortalHostnames:     []string{"portal.portcullis.test"},
		DNSRecords:          map[string]string{"demo.portcullis.test": "198.18.0.2"},
		GrantDefaultSeconds: 120, GrantMaxSeconds: 300, RevokeCooldownSeconds: 60,
		GuestSocket: "/run/portcullis/guest.sock", OperatorSocket: "/run/portcullis/operator.sock",
		PortalUID: 65534, NFTPath: "/usr/sbin/nft", ConntrackPath: "/usr/sbin/conntrack", IPPath: "/usr/sbin/ip",
		FailsafeLinkDown: true,
	}
}

func TestParseLabConfig(t *testing.T) {
	raw, err := json.Marshal(labFile())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.GatewayV4 != netip.MustParseAddr("10.203.0.1") || c.GrantMax != 5*time.Minute || len(c.ProtectedV4) != len(DefaultProtectedV4) {
		t.Fatalf("unexpected config %+v", c)
	}
	if c.PortalURL() != "http://portal.portcullis.test/" || c.PortalListen().String() != "10.203.0.1:80" {
		t.Fatalf("portal endpoints %q %s", c.PortalURL(), c.PortalListen())
	}
	if len(c.ProbeHostnames) != len(DefaultProbeHostnames) {
		t.Fatal("default probe names missing")
	}
}

func TestParseRejectsUnknownAndTrailing(t *testing.T) {
	raw, _ := json.Marshal(labFile())
	for name, input := range map[string]string{
		"unknown field": `{"guest_interface":"guest0","grant_forever":true}`,
		"trailing":      string(raw) + `{}`,
		"empty":         ``,
		"not object":    `[]`,
	} {
		if _, err := Parse([]byte(input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestValidateRejectsUnsafeTopology(t *testing.T) {
	cases := map[string]func(*File){
		"same interfaces":      func(f *File) { f.UplinkInterface = f.GuestInterface },
		"interface injection":  func(f *File) { f.GuestInterface = "guest0;flush" },
		"gateway outside":      func(f *File) { f.GatewayV4 = "10.9.0.1" },
		"gateway is network":   func(f *File) { f.GatewayV4 = "10.203.0.0" },
		"gateway in pool":      func(f *File) { f.GatewayV4 = "10.203.0.150" },
		"pool reversed":        func(f *File) { f.DHCPPoolStart, f.DHCPPoolEnd = f.DHCPPoolEnd, f.DHCPPoolStart },
		"pool has broadcast":   func(f *File) { f.DHCPPoolEnd = "10.203.0.255" },
		"subnet not canonical": func(f *File) { f.GuestSubnetV4 = "10.203.0.1/24" },
		"subnet ipv6":          func(f *File) { f.GuestSubnetV4 = "2001:db8::/64" },
		"pool too big": func(f *File) {
			f.GuestSubnetV4 = "10.0.0.0/16"
			f.GatewayV4 = "10.0.0.1"
			f.DHCPPoolStart = "10.0.1.0"
			f.DHCPPoolEnd = "10.0.9.0"
		},
		"lease too short":       func(f *File) { f.DHCPLeaseSeconds = 10 },
		"grant too long":        func(f *File) { f.GrantMaxSeconds = 3600 },
		"default above max":     func(f *File) { f.GrantDefaultSeconds = 301 },
		"grant beyond lease":    func(f *File) { f.DHCPLeaseSeconds = 120 },
		"no portal hostname":    func(f *File) { f.PortalHostnames = nil },
		"uppercase hostname":    func(f *File) { f.PortalHostnames = []string{"Portal.test"} },
		"single label hostname": func(f *File) { f.PortalHostnames = []string{"portal"} },
		"duplicate names":       func(f *File) { f.DNSRecords = map[string]string{"portal.portcullis.test": "198.18.0.2"} },
		"record into protected": func(f *File) { f.DNSRecords = map[string]string{"nas.portcullis.test": "192.168.1.10"} },
		"record ipv6":           func(f *File) { f.DNSRecords = map[string]string{"v6.portcullis.test": "2001:db8::1"} },
		"protected overlap":     func(f *File) { f.ProtectedV4 = []string{"10.0.0.0/8", "10.1.0.0/16"} },
		"protected not masked":  func(f *File) { f.ProtectedV4 = []string{"10.0.0.1/8"} },
		"protected empty":       func(f *File) { f.ProtectedV4 = []string{} },
		"relative nft":          func(f *File) { f.NFTPath = "nft" },
		"unclean path":          func(f *File) { f.IPPath = "/usr/sbin/../bin/ip" },
		"same sockets":          func(f *File) { f.OperatorSocket = f.GuestSocket },
		"root portal":           func(f *File) { f.PortalUID = 0 },
		"port zero":             func(f *File) { f.PortalPort = 0 },
		"cooldown too long":     func(f *File) { f.RevokeCooldownSeconds = 7200 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := labFile()
			mutate(&f)
			if _, err := f.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unsafe config accepted: %v", err)
			}
		})
	}
}
