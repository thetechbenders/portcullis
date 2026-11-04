package identity

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

const header = "IP address       HW type     Flags       HW address            Mask     Device\n"

const sample = header +
	"10.203.0.100     0x1         0x2         02:00:00:00:00:0a     *        guest0\n" +
	"10.203.0.101     0x1         0x0         02:00:00:00:00:0b     *        guest0\n" +
	"198.18.0.2       0x1         0x6         02:00:00:00:00:0c     *        uplink0\n" +
	"10.203.0.102     0x1         0x2         01:00:5e:00:00:01     *        guest0\n" +
	"10.203.0.103     0x20        0x2         00:11:22:33:44:55     *        ib0\n"

func TestParseProcNetARP(t *testing.T) {
	got, err := ParseProcNetARP(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Neighbor{
		{Addr: netip.MustParseAddr("10.203.0.100"), MAC: model.MAC{2, 0, 0, 0, 0, 0x0a}, Device: "guest0", Complete: true},
		{Addr: netip.MustParseAddr("10.203.0.101"), Device: "guest0"},
		{Addr: netip.MustParseAddr("198.18.0.2"), MAC: model.MAC{2, 0, 0, 0, 0, 0x0c}, Device: "uplink0", Complete: true, Permanent: true},
		{Addr: netip.MustParseAddr("10.203.0.102"), Device: "guest0", Complete: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: %+v want %+v", i, got[i], want[i])
		}
	}
	if n, err := ParseProcNetARP(strings.NewReader(header)); err != nil || len(n) != 0 {
		t.Fatalf("header only: %v %v", n, err)
	}
}

func TestParseProcNetARPRejects(t *testing.T) {
	row := "10.203.0.100     0x1         0x2         02:00:00:00:00:0a     *        guest0\n"
	for name, in := range map[string]string{
		"empty":         "",
		"no header":     row,
		"wrong header":  "IP HW Flags\n" + row,
		"columns":       header + "10.203.0.100 0x1 0x2 02:00:00:00:00:0a *\n",
		"extra column":  header + strings.TrimSuffix(row, "\n") + " x\n",
		"ipv6":          header + strings.Replace(row, "10.203.0.100", "fe80::1", 1),
		"bad ip":        header + strings.Replace(row, "10.203.0.100", "10.203.0.300", 1),
		"flags no 0x":   header + strings.Replace(row, "0x2 ", "2   ", 1),
		"flags not hex": header + strings.Replace(row, "0x2 ", "0xz ", 1),
		"bad mac":       header + strings.Replace(row, "02:00:00:00:00:0a", "02:00:00:00:00:0g", 1),
		"mask":          header + strings.Replace(row, " * ", " 1 ", 1),
		"long line":     header + strings.Repeat("x", 300) + "\n",
		"too many":      header + strings.Repeat(row, maxARPLines),
	} {
		if _, err := ParseProcNetARP(strings.NewReader(in)); !errors.Is(err, ErrARPFormat) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestProcARP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := (ProcARP{Path: path}).Neighbors(); err != nil || len(n) != 4 {
		t.Fatalf("%v %v", n, err)
	}
	if _, err := (ProcARP{Path: "relative/arp"}).Neighbors(); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := (ProcARP{Path: path + ".missing"}).Neighbors(); err == nil {
		t.Fatal("missing file accepted")
	}
}

type fakeSource struct {
	n   []model.Neighbor
	err error
}

func (f fakeSource) Neighbors() ([]model.Neighbor, error) { return f.n, f.err }

func TestCorroborate(t *testing.T) {
	addr := netip.MustParseAddr("10.203.0.100")
	mac := model.MAC{2, 0, 0, 0, 0, 0x0a}
	other := model.MAC{2, 0, 0, 0, 0, 0x0b}
	b := model.Binding{MAC: mac, Addr: addr, Expires: time.Now().Add(time.Minute)}
	ok := model.Neighbor{Addr: addr, MAC: mac, Device: "guest0", Complete: true}
	cases := []struct {
		name string
		src  NeighborSource
		addr netip.Addr
		b    model.Binding
		want error
	}{
		{"match", fakeSource{n: []model.Neighbor{ok}}, addr, b, nil},
		{"binding for other address", fakeSource{n: []model.Neighbor{ok}}, netip.MustParseAddr("10.203.0.101"), b, ErrBindingMismatch},
		{"binding zero MAC", fakeSource{n: []model.Neighbor{ok}}, addr, model.Binding{Addr: addr}, ErrBindingMismatch},
		{"empty table", fakeSource{}, addr, b, ErrNoNeighbor},
		{"incomplete only", fakeSource{n: []model.Neighbor{{Addr: addr, Device: "guest0"}}}, addr, b, ErrNoNeighbor},
		{"other device only", fakeSource{n: []model.Neighbor{{Addr: addr, MAC: mac, Device: "uplink0", Complete: true}}}, addr, b, ErrWrongInterface},
		{"different MAC", fakeSource{n: []model.Neighbor{{Addr: addr, MAC: other, Device: "guest0", Complete: true}}}, addr, b, ErrNeighborMismatch},
		{"invalid MAC entry", fakeSource{n: []model.Neighbor{{Addr: addr, Device: "guest0", Complete: true}}}, addr, b, ErrNeighborMismatch},
		{"conflicting duplicate", fakeSource{n: []model.Neighbor{ok, {Addr: addr, MAC: other, Device: "guest0", Complete: true}}}, addr, b, ErrNeighborMismatch},
		{"source error", fakeSource{err: errors.New("io")}, addr, b, ErrNeighborSource},
		{"no source", nil, addr, b, ErrNeighborSource},
	}
	for _, tc := range cases {
		c := Corroborator{Source: tc.src, Interface: "guest0"}
		if err := c.Corroborate(tc.addr, tc.b); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	if err := (Corroborator{Source: fakeSource{n: []model.Neighbor{ok}}}).Corroborate(addr, b); !errors.Is(err, ErrNeighborSource) {
		t.Errorf("empty interface: %v", err)
	}
}
