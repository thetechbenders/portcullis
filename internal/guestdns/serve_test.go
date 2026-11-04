package guestdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
)

func TestListenUDPRejectsUnsafeAddresses(t *testing.T) {
	for _, s := range []string{"0.0.0.0:53", "[::]:53", "[::1]:53", "[::ffff:127.0.0.1]:53", "127.0.0.1:0", "224.0.0.251:5353", "255.255.255.255:53"} {
		if conn, err := ListenUDP(netip.MustParseAddrPort(s)); !errors.Is(err, ErrListenAddr) || conn != nil {
			t.Errorf("%s: conn=%v err=%v", s, conn, err)
		}
	}
	if _, err := ListenUDP(netip.AddrPort{}); !errors.Is(err, ErrListenAddr) {
		t.Errorf("invalid AddrPort: %v", err)
	}
}

func TestZoneFromConfigAndValidation(t *testing.T) {
	cfg, err := config.Parse([]byte(`{"guest_interface":"guest0","uplink_interface":"uplink0",
		"gateway_v4":"10.203.0.1","guest_subnet_v4":"10.203.0.0/24","dhcp_pool_start":"10.203.0.100",
		"dhcp_pool_end":"10.203.0.199","dhcp_lease_seconds":600,"portal_port":80,"dns_port":53,
		"portal_hostnames":["portal.portcullis.test"],"dns_records":{"demo.portcullis.test":"198.18.0.2"},
		"grant_default_seconds":60,"grant_max_seconds":300,"revoke_cooldown_seconds":60,
		"guest_socket":"/run/portcullis/guest.sock","operator_socket":"/run/portcullis/operator.sock",
		"portal_uid":65534,"nft_path":"/usr/sbin/nft","conntrack_path":"/usr/sbin/conntrack","ip_path":"/usr/sbin/ip",
		"failsafe_link_down":true}`))
	if err != nil {
		t.Fatal(err)
	}
	z := ZoneFrom(cfg)
	if z.TTL != DefaultTTL || z.Records["portal.portcullis.test"] != gateway || z.Records["captive.apple.com"] != gateway ||
		z.Records["demo.portcullis.test"] != demo || len(z.Records) != 2+len(config.DefaultProbeHostnames) {
		t.Fatalf("zone %+v", z)
	}
	if _, err := NewResponder(z); err != nil {
		t.Fatal(err)
	}
	cfg.DNSRecords["portal.portcullis.test"] = demo // conflicting duplicate
	if _, err := NewResponder(ZoneFrom(cfg)); !errors.Is(err, ErrZone) {
		t.Fatalf("conflicting zone accepted: %v", err)
	}
	if _, err := NewResponder(ZoneFrom(nil)); !errors.Is(err, ErrZone) {
		t.Fatalf("empty zone accepted: %v", err)
	}
	for name, mutate := range map[string]func(*Zone){
		"uppercase":    func(z *Zone) { z.Records["Bad.Test"] = gateway },
		"trailing dot": func(z *Zone) { z.Records["bad.test."] = gateway },
		"single label": func(z *Zone) { z.Records["bad"] = gateway },
		"ipv6":         func(z *Zone) { z.Records["v6.test"] = netip.MustParseAddr("2001:db8::1") },
		"4in6":         func(z *Zone) { z.Records["m.test"] = netip.MustParseAddr("::ffff:10.0.0.1") },
		"unspecified":  func(z *Zone) { z.Records["u.test"] = netip.MustParseAddr("0.0.0.0") },
		"multicast":    func(z *Zone) { z.Records["m.test"] = netip.MustParseAddr("224.0.0.1") },
		"zero addr":    func(z *Zone) { z.Records["z.test"] = netip.Addr{} },
		"ttl zero":     func(z *Zone) { z.TTL = 0 },
		"ttl fraction": func(z *Zone) { z.TTL = 1500 * time.Millisecond },
		"ttl too long": func(z *Zone) { z.TTL = 2 * time.Hour },
		"too many": func(z *Zone) {
			for i := range MaxRecords {
				z.Records[string(rune('a'+i%26))+string(rune('a'+i/26))+".test"] = gateway
			}
		},
	} {
		z := testZone()
		mutate(&z)
		if _, err := NewResponder(z); !errors.Is(err, ErrZone) {
			t.Errorf("%s: accepted: %v", name, err)
		}
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// serve starts r.Serve on a real loopback socket and returns a connected
// client plus a function that cancels and returns Serve's result.
func serve(t *testing.T, r *Responder) (*net.UDPConn, func() error) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- r.Serve(ctx, pc) }()
	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, func() error {
		cancel()
		select {
		case err := <-errc:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after cancellation")
			return nil
		}
	}
}

func readID(t *testing.T, c *net.UDPConn, wait time.Duration) (uint16, []byte, bool) {
	t.Helper()
	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, err := c.Read(buf)
	if err != nil {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(buf), buf[:n], true
}

func TestServeLoopbackEndToEnd(t *testing.T) {
	rr := testResponder(t)
	client, stop := serve(t, rr)

	qr := query(0x1111, "portal.portcullis.test", typeA)
	binary.BigEndian.PutUint16(qr[2:4], flagQR)
	oversized := make([]byte, 600)
	copy(oversized, query(0x2222, "portal.portcullis.test", typeA))
	for _, q := range [][]byte{qr, oversized, query(0x3333, "PORTAL.portcullis.test", typeA), query(0x4444, "example.com", typeA)} {
		if _, err := client.Write(q); err != nil {
			t.Fatal(err)
		}
	}
	// Loopback preserves order: the dropped QR=1 and oversized datagrams
	// must not produce replies before the valid ones.
	id, resp, ok := readID(t, client, 2*time.Second)
	if !ok || id != 0x3333 || len(resp) != len(query(0, "PORTAL.portcullis.test", typeA))+answerLen ||
		netip.AddrFrom4([4]byte(resp[len(resp)-4:])) != gateway {
		t.Fatalf("A reply: ok=%v id=%#04x % x", ok, id, resp)
	}
	id, resp, ok = readID(t, client, 2*time.Second)
	if !ok || id != 0x4444 || resp[3]&0x0F != rcodeRefused {
		t.Fatalf("REFUSED reply: ok=%v id=%#04x % x", ok, id, resp)
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve after cancel: %v", err)
	}
	if rr.stats.dropped.Load() != 2 || rr.stats.answered.Load() != 2 {
		t.Fatalf("dropped=%d answered=%d", rr.stats.dropped.Load(), rr.stats.answered.Load())
	}
}

func TestServeRateLimitDropsBurst(t *testing.T) {
	rr := testResponder(t)
	clock := &fakeClock{t: time.Unix(1000, 0)} // frozen: buckets never refill
	rr.now = clock.Now
	rr.limits = limits{globalRate: 1, globalBurst: 100, sourceRate: 1, sourceBurst: 5, maxSources: 16}
	client, stop := serve(t, rr)
	const sent = 20
	for i := range sent {
		if _, err := client.Write(query(uint16(i), "portal.portcullis.test", typeA)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for rr.stats.answered.Load()+rr.stats.limited.Load() < sent && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := 0
	for {
		if _, _, ok := readID(t, client, 200*time.Millisecond); !ok {
			break
		}
		got++
	}
	if got != 5 || rr.stats.limited.Load() != sent-5 {
		t.Fatalf("replies=%d limited=%d, want 5 and %d", got, rr.stats.limited.Load(), sent-5)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestSourceLimiterBoundedEviction(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := newSourceLimiter(limits{sourceRate: 1, sourceBurst: 2, maxSources: 2}) // idle after 2s
	a, b, c := netip.MustParseAddr("10.203.0.100"), netip.MustParseAddr("10.203.0.101"), netip.MustParseAddr("10.203.0.102")
	if !l.allow(a, t0) || !l.allow(b, t0) {
		t.Fatal("first queries refused")
	}
	if l.allow(c, t0.Add(time.Second)) {
		t.Fatal("new source admitted while map is full of active sources")
	}
	l.allow(a, t0.Add(2500*time.Millisecond)) // keep a active
	if !l.allow(c, t0.Add(3*time.Second)) || len(l.buckets) != 2 || l.buckets[b] != nil || l.buckets[a] == nil {
		t.Fatalf("idle eviction: buckets=%v", l.buckets)
	}
}

func TestServeReturnsErrorWhenConnClosed(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if err := testResponder(t).Serve(context.Background(), pc); !errors.Is(err, ErrServe) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed conn: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := testResponder(t).Serve(ctx, pc); err != nil {
		t.Fatalf("cancelled ctx: %v", err)
	}
}
