//go:build linux

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// sockDir returns a short private directory: sun_path is limited to 108
// bytes and t.TempDir() paths can exceed it.
func sockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pcipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

type recorder struct {
	calls atomic.Int32
	last  atomic.Pointer[call]
}

type call struct {
	peer  Peer
	req   Request
	guest *GuestConn
}

func (r *recorder) Handle(_ context.Context, peer Peer, req Request, guest *GuestConn) Response {
	r.calls.Add(1)
	r.last.Store(&call{peer: peer, req: req, guest: guest})
	return Response{OK: true}
}

func startServer(t *testing.T, cfg ServerConfig, h Handler) *Server {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = filepath.Join(sockDir(t), "c.sock")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0o600
	}
	if cfg.AllowedUIDs == nil {
		cfg.AllowedUIDs = []uint32{uint32(os.Getuid())}
	}
	srv, err := Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, h) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v after cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
		if _, err := os.Lstat(cfg.Path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket file not removed: %v", err)
		}
	})
	return srv
}

// tcpPair returns a portal listener address plus the client and the
// server-side accepted connection on 127.0.0.1.
func tcpPair(t *testing.T) (netip.AddrPort, net.Conn, net.Conn) {
	t.Helper()
	ln, err := plainTCPListen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); accepted.Close() })
	return netip.MustParseAddrPort(ln.Addr().String()), client, accepted
}

// plainTCPListen disables Go's default MPTCP listeners (Go 1.24+) so the
// accepted sockets report IPPROTO_TCP, as the portal's must.
func plainTCPListen() (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
}

func guestConfig(portal netip.AddrPort) ServerConfig {
	return ServerConfig{Mode: 0o666, Guest: true, PortalAddr: portal, Ops: []Op{OpStatus, OpRequest, OpRelease}}
}

func operatorConfig() ServerConfig {
	return ServerConfig{Ops: []Op{OpSnapshot, OpReset}}
}

func fdOf(t *testing.T, c syscall.Conn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var out int
	if err := rc.Control(func(fd uintptr) { out = int(fd) }); err != nil {
		t.Fatal(err)
	}
	return out
}

// rawCall sends payload with optional descriptors, bypassing Call's checks.
func rawCall(t *testing.T, path string, payload []byte, fds ...int) (Response, error) {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var oob []byte
	if len(fds) > 0 {
		oob = syscall.UnixRights(fds...)
	}
	if _, _, err := c.WriteMsgUnix(payload, oob, nil); err != nil {
		return Response{}, err
	}
	if err := c.CloseWrite(); err != nil {
		return Response{}, err
	}
	data, err := io.ReadAll(c)
	if err != nil && len(data) == 0 {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func TestGuestCallHappyPath(t *testing.T) {
	portal, client, accepted := tcpPair(t)
	h := &recorder{}
	srv := startServer(t, guestConfig(portal), h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := Call(ctx, srv.cfg.Path, Request{Op: OpRequest, DurationSeconds: 60}, accepted)
	if err != nil || !resp.OK {
		t.Fatalf("Call = %+v, %v", resp, err)
	}
	got := h.last.Load()
	if got == nil || got.guest == nil {
		t.Fatal("handler not called with a guest connection")
	}
	wantRemote := netip.MustParseAddrPort(client.LocalAddr().String())
	if got.guest.Remote != wantRemote || got.guest.Local != portal {
		t.Fatalf("guest = %+v, want remote %s local %s", *got.guest, wantRemote, portal)
	}
	if got.peer.UID != uint32(os.Getuid()) || got.peer.PID != int32(os.Getpid()) {
		t.Fatalf("peer = %+v", got.peer)
	}
	if got.req.Op != OpRequest || got.req.DurationSeconds != 60 {
		t.Fatalf("request = %+v", got.req)
	}
	if info, err := os.Lstat(srv.cfg.Path); err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode = %v, %v", info.Mode(), err)
	}
}

func TestOperatorCall(t *testing.T) {
	h := &recorder{}
	srv := startServer(t, operatorConfig(), h)
	ctx := context.Background()
	resp, err := Call(ctx, srv.cfg.Path, Request{Op: OpSnapshot}, nil)
	if err != nil || !resp.OK {
		t.Fatalf("Call = %+v, %v", resp, err)
	}
	if got := h.last.Load(); got == nil || got.guest != nil || got.req.Op != OpSnapshot {
		t.Fatalf("handler call = %+v", got)
	}
	// An operation not configured on this socket never reaches the handler.
	resp, err = Call(ctx, srv.cfg.Path, Request{Op: OpRevoke, Target: "02:00:00:00:00:01"}, nil)
	if err != nil || resp.OK || resp.Error != ErrForbidden {
		t.Fatalf("disallowed op = %+v, %v", resp, err)
	}
	if h.calls.Load() != 1 {
		t.Fatalf("handler called %d times", h.calls.Load())
	}
}

func TestDescriptorRejections(t *testing.T) {
	portal, _, accepted := tcpPair(t)
	h := &recorder{}
	srv := startServer(t, guestConfig(portal), h)
	op := startServer(t, operatorConfig(), h)
	otherPortal := netip.AddrPortFrom(portal.Addr(), portal.Port()+1)
	wrongLocal := startServer(t, guestConfig(otherPortal), h)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	ln, err := plainTCPListen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	listenerSrv := startServer(t, guestConfig(netip.MustParseAddrPort(ln.Addr().String())), h)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	body := []byte(`{"op":"status"}`)
	tcpFD := fdOf(t, accepted.(syscall.Conn))
	cases := []struct {
		name string
		path string
		fds  []int
	}{
		{"no descriptor on guest socket", srv.cfg.Path, nil},
		{"two descriptors", srv.cfg.Path, []int{tcpFD, tcpFD}},
		{"three descriptors (truncated)", srv.cfg.Path, []int{tcpFD, tcpFD, tcpFD}},
		{"UDP socket", srv.cfg.Path, []int{fdOf(t, udp)}},
		{"listening TCP socket", listenerSrv.cfg.Path, []int{fdOf(t, ln.(*net.TCPListener))}},
		{"local address is not the portal", wrongLocal.cfg.Path, []int{tcpFD}},
		{"pipe", srv.cfg.Path, []int{int(r.Fd())}},
		{"descriptor on operator socket", op.cfg.Path, []int{tcpFD}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := rawCall(t, tc.path, body, tc.fds...)
			if err != nil || resp.OK || resp.Error != ErrForbidden {
				t.Fatalf("response = %+v, %v; want forbidden", resp, err)
			}
		})
	}
	// Call itself refuses connections without a descriptor.
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if _, err := Call(context.Background(), srv.cfg.Path, Request{Op: OpStatus}, p1); !errors.Is(err, ErrDescriptor) {
		t.Fatalf("Call with a descriptor-less guest conn = %v", err)
	}
	if n := h.calls.Load(); n != 0 {
		t.Fatalf("handler called %d times for rejected descriptors", n)
	}
}

func TestValidateGuestFDNamespaceAndPeer(t *testing.T) {
	portal, _, accepted := tcpPair(t)
	fd := fdOf(t, accepted.(syscall.Conn))
	own, err := ownNetnsCookie()
	if err != nil {
		t.Fatalf("SO_NETNS_COOKIE unsupported: %v", err)
	}
	if _, err := validateGuestFD(fd, portal, own); err != nil {
		t.Fatalf("valid fd rejected: %v", err)
	}
	if _, err := validateGuestFD(fd, portal, own+1); !errors.Is(err, ErrDescriptor) {
		t.Fatalf("foreign namespace accepted: %v", err)
	}
	gw := netip.MustParseAddrPort("10.203.0.1:80")
	for _, tc := range []struct {
		remote string
		ok     bool
	}{
		{"10.203.0.100:51000", true},
		{"127.0.0.1:51000", false},
		{"10.203.0.1:51000", false},
		{"0.0.0.0:51000", false},
		{"224.0.0.1:51000", false},
		{"255.255.255.255:51000", false},
		{"10.203.0.100:0", false},
	} {
		err := checkPeerAddr(netip.MustParseAddrPort(tc.remote), gw)
		if (err == nil) != tc.ok {
			t.Errorf("checkPeerAddr(%s) = %v, want ok=%v", tc.remote, err, tc.ok)
		}
	}
}

func TestPeerUIDRejected(t *testing.T) {
	for name, uids := range map[string][]uint32{
		"other uid":  {uint32(os.Getuid()) + 1},
		"empty list": {},
	} {
		t.Run(name, func(t *testing.T) {
			h := &recorder{}
			cfg := operatorConfig()
			cfg.AllowedUIDs = uids
			srv := startServer(t, cfg, h)
			resp, err := Call(context.Background(), srv.cfg.Path, Request{Op: OpSnapshot}, nil)
			if err == nil && (resp.OK || resp.Error != ErrForbidden) {
				t.Fatalf("unauthorized peer got %+v", resp)
			}
			if h.calls.Load() != 0 {
				t.Fatal("handler called for unauthorized peer")
			}
		})
	}
}

func TestMalformedRequests(t *testing.T) {
	h := &recorder{}
	srv := startServer(t, operatorConfig(), h)
	padded := `{"op":"snapshot"}` + strings.Repeat(" ", MaxMessageBytes-len(`{"op":"snapshot"}`))
	if resp, err := rawCall(t, srv.cfg.Path, []byte(padded)); err != nil || !resp.OK {
		t.Fatalf("request of exactly MaxMessageBytes rejected: %+v, %v", resp, err)
	}
	for name, body := range map[string]string{
		"oversized":     padded + " ",
		"unknown field": `{"op":"snapshot","client":"10.0.0.1"}`,
		"trailing data": `{"op":"snapshot"} {}`,
		"duplicate key": `{"op":"reset","op":"snapshot"}`,
		"case variant":  `{"OP":"snapshot"}`,
		"not an object": `["snapshot"]`,
		"invalid JSON":  `{"op":`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := rawCall(t, srv.cfg.Path, []byte(body))
			if err != nil || resp.OK || resp.Error != ErrBadRequest {
				t.Fatalf("response = %+v, %v; want bad_request", resp, err)
			}
		})
	}
	if _, err := Call(context.Background(), srv.cfg.Path, Request{Op: OpRevoke, Target: strings.Repeat("a", MaxMessageBytes)}, nil); !errors.Is(err, ErrMessage) {
		t.Fatalf("oversized Call = %v", err)
	}
	if h.calls.Load() != 1 {
		t.Fatalf("handler called %d times, want 1", h.calls.Load())
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestReceivedDescriptorsClosed(t *testing.T) {
	portal, _, accepted := tcpPair(t)
	h := &recorder{}
	srv := startServer(t, guestConfig(portal), h)
	op := startServer(t, operatorConfig(), h)
	tcpFD := fdOf(t, accepted.(syscall.Conn))
	ctx := context.Background()
	exercise := func() {
		if resp, err := Call(ctx, srv.cfg.Path, Request{Op: OpStatus}, accepted); err != nil || !resp.OK {
			t.Fatalf("Call = %+v, %v", resp, err)
		}
		rawCall(t, srv.cfg.Path, []byte(`{"op":"status"}`), tcpFD, tcpFD)
		rawCall(t, srv.cfg.Path, []byte(`{"op":"status"}`), tcpFD, tcpFD, tcpFD)
		rawCall(t, srv.cfg.Path, []byte(`{"op":"bogus"}`), tcpFD)
		rawCall(t, op.cfg.Path, []byte(`{"op":"snapshot"}`), tcpFD)
	}
	exercise() // warm up lazily created runtime descriptors
	before := openFDs(t)
	for range 50 {
		exercise()
	}
	deadline := time.Now().Add(2 * time.Second)
	for openFDs(t) != before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("open descriptors %d -> %d: received descriptors leaked", before, after)
	}
}

func TestListenPathSafety(t *testing.T) {
	dir := sockDir(t)
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := operatorConfig()
	cfg.Mode, cfg.AllowedUIDs, cfg.Path = 0o600, []uint32{0}, regular
	if _, err := Listen(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("regular file replaced: %v", err)
	}
	if data, _ := os.ReadFile(regular); string(data) != "keep" {
		t.Fatal("regular file modified")
	}
	// A stale socket (no listener) is replaced.
	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	cfg.Path = stale
	srv, err := Listen(cfg)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	// A live socket is not.
	if _, err := Listen(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("live socket replaced: %v", err)
	}
	srv.Close()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	cfg.Path = filepath.Join(dir, "w.sock")
	if _, err := Listen(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("world-writable directory accepted: %v", err)
	}
	for name, bad := range map[string]ServerConfig{
		"relative path":         {Path: "c.sock", Mode: 0o600, Ops: []Op{OpSnapshot}},
		"guest op on operator":  {Path: "/run/x.sock", Mode: 0o600, Ops: []Op{OpStatus}},
		"operator op on guest":  {Path: "/run/x.sock", Mode: 0o666, Guest: true, PortalAddr: netip.MustParseAddrPort("10.0.0.1:80"), Ops: []Op{OpReset}},
		"guest without portal":  {Path: "/run/x.sock", Mode: 0o666, Guest: true, Ops: []Op{OpStatus}},
		"no ops":                {Path: "/run/x.sock", Mode: 0o600},
		"setuid mode":           {Path: "/run/x.sock", Mode: 0o600 | os.ModeSetuid, Ops: []Op{OpSnapshot}},
		"negative max conns":    {Path: "/run/x.sock", Mode: 0o600, Ops: []Op{OpSnapshot}, MaxConns: -1},
		"path too long for sun": {Path: "/" + strings.Repeat("a", 120), Mode: 0o600, Ops: []Op{OpSnapshot}},
	} {
		if _, err := Listen(bad); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: Listen = %v, want ErrConfig", name, err)
		}
	}
}

func TestHandlerPanicRecovered(t *testing.T) {
	srv := startServer(t, operatorConfig(), HandlerFunc(func(context.Context, Peer, Request, *GuestConn) Response {
		panic("boom")
	}))
	for range 2 {
		resp, err := Call(context.Background(), srv.cfg.Path, Request{Op: OpSnapshot}, nil)
		if err != nil || resp.Error != ErrInternal {
			t.Fatalf("panic response = %+v, %v", resp, err)
		}
	}
}
