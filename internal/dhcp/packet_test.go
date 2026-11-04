package dhcp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

func TestParseRequest(t *testing.T) {
	raw := wire(MsgRequest, macA, 50, 4, 10, 203, 0, 100, 54, 4, 10, 203, 0, 1, 61, 7, 1, 2, 0, 0, 0, 0x0a, 1, 55, 3, 1, 3, 6)
	p, err := ParseRequest(append(raw, 0, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.MsgType != MsgRequest || p.CHAddr != macA || p.XID != 0xdeadbeef ||
		p.RequestedIP != netip.MustParseAddr("10.203.0.100") || p.ServerID != serverIP ||
		len(p.ClientID) != 7 || !bytes.Equal(p.ParamRequest, []byte{1, 3, 6}) {
		t.Fatalf("parsed %+v", p)
	}
}

func TestParseRequestRejects(t *testing.T) {
	good := wire(MsgDiscover, macA)
	mutate := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	cases := map[string][]byte{
		"short":            good[:239],
		"oversized":        append(bytes.Clone(good), make([]byte, 1500)...),
		"bootreply":        mutate(func(b []byte) []byte { b[0] = 2; return b }),
		"htype":            mutate(func(b []byte) []byte { b[1] = 6; return b }),
		"hlen":             mutate(func(b []byte) []byte { b[2] = 16; return b }),
		"hops":             mutate(func(b []byte) []byte { b[3] = 1; return b }),
		"relayed":          mutate(func(b []byte) []byte { b[24] = 10; return b }),
		"zero chaddr":      wire(MsgDiscover, model.MAC{}),
		"multicast chaddr": wire(MsgDiscover, model.MAC{1, 0, 0x5e, 0, 0, 1}),
		"chaddr padding":   mutate(func(b []byte) []byte { b[40] = 1; return b }),
		"cookie":           mutate(func(b []byte) []byte { b[236] = 0; return b }),
		"no end":           good[:len(good)-1],
		"trailing junk":    append(bytes.Clone(good), 7),
		"truncated option": append(bytes.Clone(good[:len(good)-1]), 12, 9, 'x'),
		"duplicate option": wire(MsgDiscover, macA, 12, 1, 'a', 12, 1, 'b'),
		"duplicate type":   wire(MsgDiscover, macA, 53, 1, 1),
		"overload":         wire(MsgDiscover, macA, 52, 1, 3),
		"server type":      wire(MsgAck, macA),
		"unknown type":     wire(MessageType(9), macA),
		"short ipv4":       wire(MsgRequest, macA, 50, 3, 10, 203, 0),
		"long client id":   wire(MsgDiscover, macA, append([]byte{61, 65}, make([]byte, 65)...)...),
		"no message type":  append(bytes.Clone(good[:240]), 255),
	}
	for name, b := range cases {
		if p, err := ParseRequest(b); !errors.Is(err, ErrMalformed) || p != nil {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestMarshalReply(t *testing.T) {
	s, _, _ := newTest(t, nil)
	offer := handle(t, s, pkt(MsgDiscover, macA, func(p *Packet) { p.Flags = 0x8000 }))
	b, err := offer.MarshalReply()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < minReply || b[0] != 2 || b[10] != 0x80 || !bytes.Equal(b[28:34], macA[:]) ||
		!bytes.Equal(b[16:20], []byte{10, 203, 0, 100}) {
		t.Fatalf("header % x", b[:44])
	}
	wantOpts := []byte{53, 1, 2, 54, 4, 10, 203, 0, 1, 51, 4, 0, 0, 2, 0x58, 58, 4, 0, 0, 1, 0x2c,
		59, 4, 0, 0, 2, 0x0d, 1, 4, 255, 255, 255, 0, 3, 4, 10, 203, 0, 1, 6, 4, 10, 203, 0, 1, 255}
	if !bytes.Equal(b[240:240+len(wantOpts)], wantOpts) {
		t.Fatalf("options % x", b[240:290])
	}

	nak := &Packet{MsgType: MsgNak, CHAddr: macA, ServerID: serverIP, YIAddr: netip.MustParseAddr("10.203.0.9")}
	b, err = nak.MarshalReply()
	if err != nil || !bytes.Equal(b[240:250], []byte{53, 1, 6, 54, 4, 10, 203, 0, 1, 255}) || !bytes.Equal(b[16:20], make([]byte, 4)) {
		t.Fatalf("nak %v % x", err, b[240:250])
	}
	for name, p := range map[string]*Packet{
		"request type": {MsgType: MsgRequest, CHAddr: macA, ServerID: serverIP},
		"zero chaddr":  {MsgType: MsgNak, ServerID: serverIP},
		"no server id": {MsgType: MsgNak, CHAddr: macA},
		"no timers":    {MsgType: MsgAck, CHAddr: macA, ServerID: serverIP, YIAddr: serverIP, Router: serverIP, DNS: serverIP},
	} {
		if _, err := p.MarshalReply(); !errors.Is(err, ErrReply) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(wire(MsgDiscover, macA))
	f.Add(wire(MsgRequest, macA, 50, 4, 10, 203, 0, 100, 54, 4, 10, 203, 0, 1))
	f.Add(wire(MsgRelease, macA, 54, 4, 10, 203, 0, 1))
	f.Add(wire(MsgDecline, macA, 50, 4, 10, 203, 0, 100, 61, 2, 1, 2))
	f.Add(wire(MsgDiscover, macA)[:250])
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseRequest(b)
		if err != nil {
			return
		}
		if _, err := model.MACFromBytes(p.CHAddr[:]); err != nil || !clientMessage(p.MsgType) || len(p.ClientID) > maxClientID {
			t.Fatalf("invariants violated: %+v", p)
		}
		s, err := NewServer(testConfig(), &recSink{}, func() time.Time { return time.Unix(1e9, 0) }, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := s.Handle(context.Background(), p)
		if err == nil && r != nil {
			if _, err := r.MarshalReply(); err != nil {
				t.Fatalf("server built an invalid reply: %v", err)
			}
		}
	})
}

type datagram struct {
	b    []byte
	addr net.Addr
}

// fakeConn is an in-memory PacketConn; nothing touches a real network.
type fakeConn struct {
	in     chan datagram
	out    chan datagram
	mu     sync.Mutex
	dl     time.Time
	wake   chan struct{}
	closed chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan datagram, 64), out: make(chan datagram, 64), wake: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (c *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dl := c.dl
		c.mu.Unlock()
		timer := time.NewTimer(time.Until(dl))
		select {
		case d := <-c.in:
			timer.Stop()
			return copy(b, d.b), d.addr, nil
		case <-timer.C:
			return 0, nil, os.ErrDeadlineExceeded
		case <-c.wake:
			timer.Stop()
		case <-c.closed:
			timer.Stop()
			return 0, nil, net.ErrClosed
		}
	}
}

func (c *fakeConn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.out <- datagram{bytes.Clone(b), a}
	return len(b), nil
}
func (c *fakeConn) Close() error                     { close(c.closed); return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.UDPAddr{Port: 67} }
func (c *fakeConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.dl = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

func TestServeBroadcastsRepliesAndDropsJunk(t *testing.T) {
	s, sink, clk := newTest(t, nil)
	s.sweepInterval = 20 * time.Millisecond
	conn := newFakeConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, conn) }()

	client := &net.UDPAddr{IP: net.IPv4zero, Port: 68}
	conn.in <- datagram{[]byte("junk"), client}
	conn.in <- datagram{wire(MsgDiscover, macB), &net.UDPAddr{IP: net.IPv4zero, Port: 1068}}
	conn.in <- datagram{wire(MsgDiscover, macA), client}
	select {
	case d := <-conn.out:
		if d.addr.String() != "255.255.255.255:68" || d.b[0] != 2 || !bytes.Equal(d.b[28:34], macA[:]) {
			t.Fatalf("reply to %s % x", d.addr, d.b[:34])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply")
	}
	select {
	case d := <-conn.out:
		t.Fatalf("junk or wrong-port datagram answered: % x", d.b[:34])
	case <-time.After(50 * time.Millisecond):
	}

	// Periodic sweep inside the loop ends expired bindings.
	if err := s.Adopt(model.Binding{MAC: macB, Addr: netip.MustParseAddr("10.203.0.150"), Expires: clk.now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	clk.add(2 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for len(sink.log()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ev := sink.log(); len(ev) != 1 || ev[0] != "unbind 02:00:00:00:0b:01 10.203.0.150 lease-expired" {
		t.Fatalf("sweep events %v", ev)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop on cancellation")
	}
}

func TestServeRateLimitsPerMAC(t *testing.T) {
	s, _, _ := newTest(t, nil) // frozen clock: buckets never refill
	conn := newFakeConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, conn)
	client := &net.UDPAddr{IP: net.IPv4zero, Port: 68}
	for range 15 {
		conn.in <- datagram{wire(MsgDiscover, macA), client}
	}
	replies := 0
	for {
		select {
		case <-conn.out:
			replies++
			continue
		case <-time.After(200 * time.Millisecond):
		}
		break
	}
	if replies != int(macBurst) {
		t.Fatalf("%d replies, want %d", replies, int(macBurst))
	}
}

func TestListenInterfaceValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		port int
	}{{"guest0;rm", 67}, {"", 67}, {"guest0", 0}, {"guest0", 70000}} {
		if c, err := ListenInterface(tc.name, tc.port); !errors.Is(err, ErrInvalidConfig) {
			if c != nil {
				c.Close()
			}
			t.Errorf("%q:%d accepted", tc.name, tc.port)
		}
	}
}
