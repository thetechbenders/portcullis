package dhcp

import (
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
)

func TestConfigFromLab(t *testing.T) {
	c, err := config.File{
		GuestInterface: "guest0", UplinkInterface: "uplink0",
		GatewayV4: "10.203.0.1", GuestSubnetV4: "10.203.0.0/24",
		DHCPPoolStart: "10.203.0.100", DHCPPoolEnd: "10.203.0.199", DHCPLeaseSeconds: 600,
		PortalPort: 80, DNSPort: 53, PortalHostnames: []string{"portal.portcullis.test"},
		GrantDefaultSeconds: 60, GrantMaxSeconds: 300,
		GuestSocket: "/run/portcullis/guest.sock", OperatorSocket: "/run/portcullis/operator.sock",
		PortalUID: 65534, NFTPath: "/usr/sbin/nft", ConntrackPath: "/usr/sbin/conntrack", IPPath: "/usr/sbin/ip",
		FailsafeLinkDown: true,
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	got := ConfigFrom(c)
	if got != testConfig() {
		t.Fatalf("ConfigFrom = %+v", got)
	}
	if got.OfferTimeout != 30*time.Second || got.MaxBindings != 100 || got.Validate() != nil {
		t.Fatal("unexpected derived defaults")
	}
}
