package kernel

import (
	"fmt"
	"testing"
)

func TestUpperDevices(t *testing.T) {
	base := `{"ifindex":2,"ifname":"guest0","flags":[],"link_index":7,"link_netnsid":0},{"ifindex":3,"ifname":"uplink0","flags":[]}`
	for _, tc := range []struct {
		name, extra string
		bad         bool
	}{
		{"plain", "", false},
		{"unrelated", `,{"ifindex":4,"ifname":"dummy0","flags":[]}`, false},
		{"remote peer", `,{"ifindex":4,"ifname":"veth0","link_index":2,"link_netnsid":0}`, false},
		{"vlan", `,{"ifindex":4,"ifname":"vlan0","link_index":2,"linkinfo":{"info_kind":"vlan"}}`, true},
		{"macvlan", `,{"ifindex":4,"ifname":"mac0","link":"guest0","linkinfo":{"info_kind":"macvlan"}}`, true},
		{"ipvlan uplink", `,{"ifindex":4,"ifname":"ip0","link_index":3,"linkinfo":{"info_kind":"ipvlan"}}`, true},
		{"invalid index", `,{"ifindex":4,"ifname":"bad0","link_index":"2"}`, true},
		{"duplicate field", `,{"ifindex":4,"ifname":"bad0","link_index":8,"link_index":2}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyNoUpperLinks([]byte(fmt.Sprintf("[%s%s]", base, tc.extra)), "guest0", "uplink0")
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v, want rejection=%v", err, tc.bad)
			}
		})
	}
}
