package dhcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	serverIP = netip.MustParseAddr("10.203.0.1")
	macA     = model.MAC{2, 0, 0, 0, 0x0a, 1}
	macB     = model.MAC{2, 0, 0, 0, 0x0b, 1}
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recSink struct {
	mu      sync.Mutex
	events  []string
	bindErr error
	srv     *Server // if set, Bind re-enters the server's read API
}

func (r *recSink) Bind(_ context.Context, b model.Binding) error {
	if r.srv != nil {
		r.srv.Lookup(b.Addr)
		r.srv.Bindings()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, fmt.Sprintf("bind %s %s", b.MAC, b.Addr))
	return r.bindErr
}

func (r *recSink) Unbind(_ context.Context, b model.Binding, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, fmt.Sprintf("unbind %s %s %s", b.MAC, b.Addr, reason))
}

func (r *recSink) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func testConfig() Config {
	return Config{
		Interface: "guest0", ServerIP: serverIP, Subnet: netip.MustParsePrefix("10.203.0.0/24"),
		PoolStart: netip.MustParseAddr("10.203.0.100"), PoolEnd: netip.MustParseAddr("10.203.0.199"),
		Router: serverIP, DNS: serverIP, LeaseTime: 600 * time.Second,
		OfferTimeout: 30 * time.Second, DeclineQuarantine: 10 * time.Minute, MaxBindings: 100,
	}
}

func newTest(t *testing.T, mutate func(*Config)) (*Server, *recSink, *clock) {
	t.Helper()
	cfg := testConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	sink := &recSink{}
	clk := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	s, err := NewServer(cfg, sink, clk.now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, sink, clk
}

func pkt(t MessageType, mac model.MAC, mut func(*Packet)) *Packet {
	zero := netip.AddrFrom4([4]byte{})
	p := &Packet{Op: 1, HType: 1, HLen: 6, XID: 0x1234, CHAddr: mac, MsgType: t,
		CIAddr: zero, YIAddr: zero, SIAddr: zero, GIAddr: zero}
	if mut != nil {
		mut(p)
	}
	return p
}

func handle(t *testing.T, s *Server, p *Packet) *Packet {
	t.Helper()
	r, err := s.Handle(context.Background(), p)
	if err != nil {
		t.Fatalf("handle %s: %v", p.MsgType, err)
	}
	return r
}

// dora runs DISCOVER/REQUEST for mac and returns the ACKed address.
func dora(t *testing.T, s *Server, mac model.MAC) netip.Addr {
	t.Helper()
	offer := handle(t, s, pkt(MsgDiscover, mac, nil))
	if offer == nil || offer.MsgType != MsgOffer {
		t.Fatalf("no offer: %+v", offer)
	}
	ack := handle(t, s, pkt(MsgRequest, mac, func(p *Packet) { p.ServerID, p.RequestedIP = serverIP, offer.YIAddr }))
	if ack == nil || ack.MsgType != MsgAck || ack.YIAddr != offer.YIAddr {
		t.Fatalf("no ack: %+v", ack)
	}
	return ack.YIAddr
}

func TestDORAAndRenew(t *testing.T) {
	s, sink, clk := newTest(t, nil)
	sink.srv = s // Bind re-enters Lookup/Bindings: must not deadlock
	addr := dora(t, s, macA)
	if addr != netip.MustParseAddr("10.203.0.100") {
		t.Fatalf("lowest free address not chosen: %s", addr)
	}
	b, ok := s.Lookup(addr)
	if !ok || b.MAC != macA || !b.Expires.Equal(clk.now().Add(600*time.Second)) {
		t.Fatalf("binding %+v %v", b, ok)
	}
	if got := dora(t, s, macB); got != netip.MustParseAddr("10.203.0.101") {
		t.Fatalf("second client got %s", got)
	}
	// Repeated DISCOVER from a bound MAC re-offers its binding.
	if r := handle(t, s, pkt(MsgDiscover, macA, nil)); r.YIAddr != addr {
		t.Fatalf("rediscover offered %s", r.YIAddr)
	}

	clk.add(300 * time.Second)
	for _, broadcast := range []uint16{0, 0x8000} { // RENEWING, REBINDING
		r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) { p.CIAddr, p.Flags = addr, broadcast }))
		if r == nil || r.MsgType != MsgAck || r.CIAddr != addr || r.Flags != broadcast {
			t.Fatalf("renew: %+v", r)
		}
	}
	if b, _ := s.Lookup(addr); !b.Expires.Equal(clk.now().Add(600 * time.Second)) {
		t.Fatal("renewal did not extend the lease")
	}
	// INIT-REBOOT for the held address is acknowledged.
	if r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) { p.RequestedIP = addr })); r.MsgType != MsgAck {
		t.Fatalf("init-reboot: %+v", r)
	}
	if got := s.Bindings(); len(got) != 2 || got[0].Addr != addr {
		t.Fatalf("bindings %+v", got)
	}
	if mb, ok := s.LookupMAC(macB); !ok || mb.Addr != netip.MustParseAddr("10.203.0.101") {
		t.Fatalf("LookupMAC %+v", mb)
	}
}

func TestNAKs(t *testing.T) {
	s, sink, _ := newTest(t, nil)
	addrA := dora(t, s, macA)
	cases := map[string]*Packet{
		"init-reboot other network":   pkt(MsgRequest, macB, func(p *Packet) { p.RequestedIP = netip.MustParseAddr("192.168.1.50") }),
		"init-reboot address of A":    pkt(MsgRequest, macB, func(p *Packet) { p.RequestedIP = addrA }),
		"init-reboot without binding": pkt(MsgRequest, macB, func(p *Packet) { p.RequestedIP = netip.MustParseAddr("10.203.0.150") }),
		"renew foreign ciaddr":        pkt(MsgRequest, macB, func(p *Packet) { p.CIAddr = addrA }),
		"select unoffered address":    pkt(MsgRequest, macB, func(p *Packet) { p.ServerID, p.RequestedIP = serverIP, addrA }),
	}
	for name, p := range cases {
		r := handle(t, s, p)
		if r == nil || r.MsgType != MsgNak || r.YIAddr.IsValid() && !r.YIAddr.IsUnspecified() {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if b, ok := s.Lookup(addrA); !ok || b.MAC != macA {
		t.Fatal("NAKs to another MAC disturbed A's binding")
	}
	// A NAK to a MAC with a binding elsewhere ends that stale binding.
	r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) { p.RequestedIP = netip.MustParseAddr("10.203.0.150") }))
	if r.MsgType != MsgNak {
		t.Fatal("expected NAK")
	}
	if _, ok := s.Lookup(addrA); ok {
		t.Fatal("stale binding survived NAK")
	}
	if ev := sink.log(); ev[len(ev)-1] != "unbind 02:00:00:00:0a:01 10.203.0.100 dhcp-nak" {
		t.Fatalf("events %v", ev)
	}
}

func TestWrongServerIDDropsOffer(t *testing.T) {
	s, _, _ := newTest(t, nil)
	offer := handle(t, s, pkt(MsgDiscover, macA, nil))
	r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) {
		p.ServerID, p.RequestedIP = netip.MustParseAddr("10.203.0.2"), offer.YIAddr
	}))
	if r != nil {
		t.Fatalf("replied to another server's selection: %+v", r)
	}
	if o := handle(t, s, pkt(MsgDiscover, macB, nil)); o.YIAddr != offer.YIAddr {
		t.Fatal("dropped offer was not released for reuse")
	}
}

func TestBindFailureMeansNoAck(t *testing.T) {
	s, sink, _ := newTest(t, nil)
	sink.bindErr = errors.New("nft failed")
	offer := handle(t, s, pkt(MsgDiscover, macA, nil))
	r, err := s.Handle(context.Background(), pkt(MsgRequest, macA, func(p *Packet) { p.ServerID, p.RequestedIP = serverIP, offer.YIAddr }))
	if r != nil || !errors.Is(err, ErrBind) || !errors.Is(err, sink.bindErr) {
		t.Fatalf("reply=%+v err=%v", r, err)
	}
	if _, ok := s.Lookup(offer.YIAddr); ok || len(s.Bindings()) != 0 {
		t.Fatal("binding recorded without kernel evidence")
	}
	if ev := sink.log(); len(ev) != 2 || ev[1] != "unbind 02:00:00:00:0a:01 10.203.0.100 bind-failed" {
		t.Fatalf("events %v", ev)
	}
}

func TestReleaseAndDecline(t *testing.T) {
	s, sink, clk := newTest(t, nil)
	addr := dora(t, s, macA)
	// Release naming the wrong ciaddr or from another MAC is ignored.
	handle(t, s, pkt(MsgRelease, macB, func(p *Packet) { p.CIAddr, p.ServerID = addr, serverIP }))
	handle(t, s, pkt(MsgRelease, macA, func(p *Packet) { p.CIAddr, p.ServerID = netip.MustParseAddr("10.203.0.150"), serverIP }))
	if _, ok := s.Lookup(addr); !ok {
		t.Fatal("mismatched release removed binding")
	}
	if r := handle(t, s, pkt(MsgRelease, macA, func(p *Packet) { p.CIAddr, p.ServerID = addr, serverIP })); r != nil {
		t.Fatal("release must not be answered")
	}
	if _, ok := s.Lookup(addr); ok {
		t.Fatal("release kept binding")
	}

	addr = dora(t, s, macA)
	handle(t, s, pkt(MsgDecline, macA, func(p *Packet) { p.RequestedIP, p.ServerID = addr, serverIP }))
	ev := sink.log()
	if ev[1] != "unbind 02:00:00:00:0a:01 10.203.0.100 dhcp-release" || ev[3] != "unbind 02:00:00:00:0a:01 10.203.0.100 dhcp-decline" {
		t.Fatalf("events %v", ev)
	}
	if o := handle(t, s, pkt(MsgDiscover, macB, nil)); o.YIAddr == addr {
		t.Fatal("quarantined address offered")
	}
	clk.add(10*time.Minute + time.Second)
	if o := handle(t, s, pkt(MsgDiscover, macA, nil)); o.YIAddr != addr {
		t.Fatalf("quarantine did not end: %s", o.YIAddr)
	}
}

func TestExpiryUnbindsBeforeReassignment(t *testing.T) {
	for _, viaSweep := range []bool{false, true} {
		single := func(c *Config) { c.PoolEnd, c.MaxBindings = c.PoolStart, 1 }
		s, sink, clk := newTest(t, single)
		addr := dora(t, s, macA)
		if r := handle(t, s, pkt(MsgDiscover, macB, nil)); r != nil {
			t.Fatal("offered an address that is still bound")
		}
		clk.add(600 * time.Second)
		if _, ok := s.Lookup(addr); ok {
			t.Fatal("expired binding still visible")
		}
		if viaSweep && s.Sweep(context.Background()) != 1 {
			t.Fatal("sweep did not expire binding")
		}
		if got := dora(t, s, macB); got != addr {
			t.Fatalf("reassignment got %s", got)
		}
		want := []string{
			"bind 02:00:00:00:0a:01 10.203.0.100",
			"unbind 02:00:00:00:0a:01 10.203.0.100 lease-expired",
			"bind 02:00:00:00:0b:01 10.203.0.100",
		}
		if ev := sink.log(); fmt.Sprint(ev) != fmt.Sprint(want) {
			t.Fatalf("sweep=%v order %v", viaSweep, ev)
		}
	}
}

func TestOfferExpiry(t *testing.T) {
	s, _, clk := newTest(t, nil)
	offer := handle(t, s, pkt(MsgDiscover, macA, nil))
	clk.add(31 * time.Second)
	if o := handle(t, s, pkt(MsgDiscover, macB, nil)); o.YIAddr != offer.YIAddr {
		t.Fatal("expired offer still reserved")
	}
	r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) { p.ServerID, p.RequestedIP = serverIP, offer.YIAddr }))
	if r.MsgType != MsgNak {
		t.Fatalf("stale selection acknowledged: %+v", r)
	}
}

func TestAdoptValidation(t *testing.T) {
	s, sink, clk := newTest(t, nil)
	now := clk.now()
	good := model.Binding{MAC: macA, Addr: netip.MustParseAddr("10.203.0.120"), Expires: now.Add(time.Minute)}
	if err := s.Adopt(good); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]model.Binding{
		"duplicate address": {MAC: macB, Addr: good.Addr, Expires: now.Add(time.Minute)},
		"duplicate MAC":     {MAC: macA, Addr: netip.MustParseAddr("10.203.0.121"), Expires: now.Add(time.Minute)},
		"outside pool":      {MAC: macB, Addr: netip.MustParseAddr("10.203.0.50"), Expires: now.Add(time.Minute)},
		"gateway":           {MAC: macB, Addr: serverIP, Expires: now.Add(time.Minute)},
		"expired":           {MAC: macB, Addr: netip.MustParseAddr("10.203.0.121"), Expires: now},
		"longer than lease": {MAC: macB, Addr: netip.MustParseAddr("10.203.0.121"), Expires: now.Add(time.Hour)},
		"zero MAC":          {Addr: netip.MustParseAddr("10.203.0.121"), Expires: now.Add(time.Minute)},
		"multicast MAC":     {MAC: model.MAC{1, 0, 0x5e, 0, 0, 1}, Addr: netip.MustParseAddr("10.203.0.121"), Expires: now.Add(time.Minute)},
	} {
		if err := s.Adopt(b); !errors.Is(err, ErrAdopt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(sink.log()) != 0 {
		t.Fatal("Adopt must not call the sink")
	}
	// The adopted client renews without a fresh DORA.
	if r := handle(t, s, pkt(MsgRequest, macA, func(p *Packet) { p.CIAddr = good.Addr })); r.MsgType != MsgAck {
		t.Fatal("adopted binding not renewable")
	}
}

func TestHandleRejectsRelayedAndInvalid(t *testing.T) {
	s, _, _ := newTest(t, nil)
	for name, p := range map[string]*Packet{
		"giaddr":  pkt(MsgDiscover, macA, func(p *Packet) { p.GIAddr = netip.MustParseAddr("10.9.9.9") }),
		"hops":    pkt(MsgDiscover, macA, func(p *Packet) { p.Hops = 1 }),
		"reply":   pkt(MsgOffer, macA, nil),
		"zeromac": pkt(MsgDiscover, model.MAC{}, nil),
		"nil":     nil,
	} {
		if r, err := s.Handle(context.Background(), p); r != nil || !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v %v", name, r, err)
		}
	}
}

func TestConcurrentClientsGetUniqueAddresses(t *testing.T) {
	s, _, _ := newTest(t, nil)
	var wg sync.WaitGroup
	got := make([]netip.Addr, 50)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mac := model.MAC{2, 0, 0, 1, 0, byte(i)}
			o, _ := s.Handle(context.Background(), pkt(MsgDiscover, mac, nil))
			if o == nil {
				return
			}
			a, _ := s.Handle(context.Background(), pkt(MsgRequest, mac, func(p *Packet) { p.ServerID, p.RequestedIP = serverIP, o.YIAddr }))
			if a != nil && a.MsgType == MsgAck {
				got[i] = a.YIAddr
			}
		}()
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for _, a := range got {
		if !a.IsValid() || seen[a] {
			t.Fatalf("missing or duplicate address in %v", got)
		}
		seen[a] = true
	}
	if len(s.Bindings()) != 50 {
		t.Fatal("binding count")
	}
}

func TestNewServerValidation(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"pool outside subnet": func(c *Config) { c.PoolEnd = netip.MustParseAddr("10.203.1.5") },
		"pool has server":     func(c *Config) { c.PoolStart = netip.MustParseAddr("10.203.0.1") },
		"pool has broadcast":  func(c *Config) { c.PoolEnd = netip.MustParseAddr("10.203.0.255") },
		"pool has network":    func(c *Config) { c.PoolStart = netip.MustParseAddr("10.203.0.0") },
		"short lease":         func(c *Config) { c.LeaseTime = 59 * time.Second },
		"fractional lease":    func(c *Config) { c.LeaseTime = 90*time.Second + 1 },
		"too many bindings":   func(c *Config) { c.MaxBindings = 101 },
		"bad interface":       func(c *Config) { c.Interface = "guest0;x" },
		"IPv6 server":         func(c *Config) { c.ServerIP = netip.MustParseAddr("fe80::1") },
	} {
		cfg := testConfig()
		mut(&cfg)
		if _, err := NewServer(cfg, &recSink{}, nil, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewServer(testConfig(), nil, nil, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Error("nil sink accepted")
	}
}

// wire builds a raw client message for codec tests.
func wire(t MessageType, mac model.MAC, opts ...byte) []byte {
	b := make([]byte, minPacket)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:], 0xdeadbeef)
	copy(b[28:], mac[:])
	copy(b[236:], magicCookie)
	b = append(b, optMessageType, 1, byte(t))
	b = append(b, opts...)
	return append(b, optEnd)
}
