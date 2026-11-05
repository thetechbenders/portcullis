package hostpreflight

import (
	"testing"
)

func TestProcRoutesIPv6NullAndUsableDefault(t *testing.T) {
	zero := "00000000000000000000000000000000"
	loop := "00000000000000000000000000000001"
	lines := []string{
		zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000000 00000000 00200200 lo",
		zero + " 00 " + zero + " 00 " + zero + " 00000064 00000000 00000000 00000003 eth0",
		loop + " 80 " + zero + " 00 " + zero + " 00000000 00000000 00000000 00000001 lo",
	}
	got, err := ParseProcRoutes("ipv6", lines)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Default || got[0].Interface != "eth0" ||
		got[1].Default || got[1].Destination != "::1/128" {
		t.Fatalf("IPv6 rejected/null route mistaken for default: %+v", got)
	}
}

func TestProcRoutesIPv4FlagsAndSpecificRoute(t *testing.T) {
	lines := []string{
		"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT",
		"eth0 00000000 0100A8C0 0003 0 0 0 00000000 0 0 0",
		"wlan0 0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0",
		"lo 00000000 00000000 0201 0 0 0 00000000 0 0 0",
		"lo 00000000 00000000 0000 0 0 0 00000000 0 0 0",
	}
	got, err := ParseProcRoutes("ipv4", lines)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Default || got[0].Interface != "eth0" ||
		got[1].Destination != "192.168.0.0/24" || got[1].Default {
		t.Fatalf("unexpected parsed IPv4 routes: %+v", got)
	}
}

func TestMalformedProcRoutesFailRatherThanInventEmpty(t *testing.T) {
	for _, tc := range []struct{ family string; lines []string }{
		{"ipv4", []string{"eth0 0"}},
		{"ipv4", []string{"eth0 00000000 00000000 invalid 0 0 0 00000000"}},
		{"ipv6", []string{"bad"}},
		{"ipv6", []string{"00000000000000000000000000000000 00 0 00 0 0 0 0 nope eth0"}},
	} {
		if _, err := ParseProcRoutes(tc.family, tc.lines); err == nil {
			t.Fatalf("malformed %s proc route accepted: %v", tc.family, tc.lines)
		}
	}
}
