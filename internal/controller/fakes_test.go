package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/model"
)

var errInjected = errors.New("injected failure")

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// fakeElem models one nft set element; timeout 0 means untimed (never expires).
type fakeElem struct {
	timeout  time.Duration
	deadline time.Time
}

// fakeKernel models the three guard sets with per-element kernel timeouts
// against the fake clock, and records every call.
type fakeKernel struct {
	mu         sync.Mutex
	clk        *fakeClock
	bound      map[pair]fakeElem
	granted    map[pair]fakeElem
	dst        map[netip.Addr]fakeElem
	calls      map[string]int
	fail       map[string]error
	dropGrant  bool
	violations []string
}

func newFakeKernel(clk *fakeClock) *fakeKernel {
	return &fakeKernel{clk: clk, bound: map[pair]fakeElem{}, granted: map[pair]fakeElem{},
		dst: map[netip.Addr]fakeElem{}, calls: map[string]int{}, fail: map[string]error{}}
}

func (k *fakeKernel) elem(ttl time.Duration) fakeElem {
	if ttl == 0 {
		return fakeElem{}
	}
	return fakeElem{timeout: ttl, deadline: k.clk.Now().Add(ttl)}
}

func (k *fakeKernel) enter(name string) error {
	k.calls[name]++
	now := k.clk.Now()
	for p, e := range k.bound {
		if e.timeout > 0 && !now.Before(e.deadline) {
			delete(k.bound, p)
		}
	}
	for p, e := range k.granted {
		if e.timeout > 0 && !now.Before(e.deadline) {
			delete(k.granted, p)
		}
	}
	for a, e := range k.dst {
		if e.timeout > 0 && !now.Before(e.deadline) {
			delete(k.dst, a)
		}
	}
	return k.fail[name]
}

func (k *fakeKernel) toElement(addr netip.Addr, mac model.MAC, e fakeElem) model.Element {
	el := model.Element{Addr: addr, MAC: mac, Timeout: e.timeout}
	if e.timeout > 0 {
		el.Expires = e.deadline.Sub(k.clk.Now()).Truncate(time.Second)
	}
	return el
}

func (k *fakeKernel) stateLocked() model.KernelState {
	var ks model.KernelState
	for p, e := range k.bound {
		ks.Bound = append(ks.Bound, k.toElement(p.addr, p.mac, e))
	}
	for p, e := range k.granted {
		ks.Granted = append(ks.Granted, k.toElement(p.addr, p.mac, e))
	}
	for a, e := range k.dst {
		ks.GrantedDst = append(ks.GrantedDst, k.toElement(a, model.MAC{}, e))
	}
	ks.Counters = []model.Counter{{Rule: "guest-egress", Packets: 7, Bytes: 420}}
	return ks
}

func (k *fakeKernel) checkTTL(what string, ttl, limit time.Duration) {
	if ttl%time.Second != 0 || ttl < time.Second || ttl > limit {
		k.violations = append(k.violations, fmt.Sprintf("%s ttl %v", what, ttl))
	}
}

func (k *fakeKernel) Attest(context.Context) (model.KernelState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Attest"); err != nil {
		return model.KernelState{}, err
	}
	return k.stateLocked(), nil
}

func (k *fakeKernel) Snapshot(context.Context) (model.KernelState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Snapshot"); err != nil {
		return model.KernelState{}, err
	}
	return k.stateLocked(), nil
}

func (k *fakeKernel) Bind(_ context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Bind"); err != nil {
		return err
	}
	k.checkTTL("bind", ttl, 2*time.Hour)
	k.bound[pair{ip, mac}] = k.elem(ttl)
	return nil
}

func (k *fakeKernel) Unbind(_ context.Context, ip netip.Addr, mac model.MAC) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Unbind"); err != nil {
		return err
	}
	delete(k.bound, pair{ip, mac})
	return nil
}

func (k *fakeKernel) Grant(_ context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Grant"); err != nil {
		return err
	}
	k.checkTTL("grant", ttl, 15*time.Minute)
	if k.dropGrant {
		return nil
	}
	k.granted[pair{ip, mac}] = k.elem(ttl)
	k.dst[ip] = k.elem(ttl)
	return nil
}

func (k *fakeKernel) Revoke(_ context.Context, ip netip.Addr, mac model.MAC) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("Revoke"); err != nil {
		return err
	}
	delete(k.granted, pair{ip, mac})
	delete(k.dst, ip)
	return nil
}

func (k *fakeKernel) RevokeDst(_ context.Context, ip netip.Addr) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("RevokeDst"); err != nil {
		return err
	}
	delete(k.dst, ip)
	return nil
}

func (k *fakeKernel) FlushGrants(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.enter("FlushGrants"); err != nil {
		return err
	}
	clear(k.granted)
	clear(k.dst)
	return nil
}

func (k *fakeKernel) setFail(name string, err error) { k.mu.Lock(); k.fail[name] = err; k.mu.Unlock() }
func (k *fakeKernel) count(name string) int          { k.mu.Lock(); defer k.mu.Unlock(); return k.calls[name] }

func (k *fakeKernel) injectGranted(ip netip.Addr, mac model.MAC, ttl time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.granted[pair{ip, mac}] = k.elem(ttl)
}

func (k *fakeKernel) injectDst(ip netip.Addr, ttl time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dst[ip] = k.elem(ttl)
}

func (k *fakeKernel) injectBound(ip netip.Addr, mac model.MAC, ttl time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.bound[pair{ip, mac}] = k.elem(ttl)
}

func (k *fakeKernel) grantCounts() (granted, dst int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.enter("inspect")
	return len(k.granted), len(k.dst)
}

func (k *fakeKernel) hasBound(ip netip.Addr, mac model.MAC) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.enter("inspect")
	_, ok := k.bound[pair{ip, mac}]
	return ok
}

type fakeFlows struct {
	mu      sync.Mutex
	flushed []netip.Addr
}

func (f *fakeFlows) Flush(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushed = append(f.flushed, ip)
	return nil
}

func (f *fakeFlows) has(ip netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.flushed, ip)
}

type fakeEvidence struct {
	mu   sync.Mutex
	errs map[netip.Addr]error
}

func (e *fakeEvidence) Corroborate(addr netip.Addr, b model.Binding) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if b.Addr != addr {
		return errors.New("binding mismatch")
	}
	return e.errs[addr]
}

type fakeFailsafe struct {
	mu  sync.Mutex
	n   int
	err error
}

func (f *fakeFailsafe) Engage(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return f.err
}

func (f *fakeFailsafe) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeFailsafe) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

// fakeDHCP mimics the real DHCP server's locking: it holds its own mutex
// while calling the sink, which is what makes a controller→DHCP call under
// the controller mutex a deadlock.
type fakeDHCP struct {
	mu      sync.Mutex
	clk     *fakeClock
	m       map[netip.Addr]model.Binding
	adopted []model.Binding
}

func (d *fakeDHCP) Lookup(a netip.Addr) (model.Binding, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.m[a]
	return b, ok && d.clk.Now().Before(b.Expires)
}

func (d *fakeDHCP) Bindings() []model.Binding {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []model.Binding
	for _, b := range d.m {
		if d.clk.Now().Before(b.Expires) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b model.Binding) int { return a.Addr.Compare(b.Addr) })
	return out
}

func (d *fakeDHCP) Adopt(b model.Binding) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.m[b.Addr]; ok {
		return errors.New("duplicate")
	}
	d.m[b.Addr] = b
	d.adopted = append(d.adopted, b)
	return nil
}

func (d *fakeDHCP) bind(ctx context.Context, c *Controller, b model.Binding) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := c.Bind(ctx, b); err != nil {
		return err
	}
	d.m[b.Addr] = b
	return nil
}

func (d *fakeDHCP) release(ctx context.Context, c *Controller, b model.Binding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.m, b.Addr)
	c.Unbind(ctx, b, "dhcp-release")
}

var (
	subnet  = netip.MustParsePrefix("10.203.0.0/24")
	gateway = netip.MustParseAddr("10.203.0.1")
	addrA   = netip.MustParseAddr("10.203.0.100")
	addrB   = netip.MustParseAddr("10.203.0.101")
	macA    = mustMAC("02:00:00:00:0a:01")
	macB    = mustMAC("02:00:00:00:0b:01")
)

func mustMAC(s string) model.MAC {
	m, err := model.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

type env struct {
	t    *testing.T
	clk  *fakeClock
	k    *fakeKernel
	fl   *fakeFlows
	ev   *fakeEvidence
	fs   *fakeFailsafe
	dhcp *fakeDHCP
	c    *Controller
	logs *bytes.Buffer
}

func testConfig() Config {
	return Config{GuestSubnet: subnet, Gateway: gateway, GrantDefault: time.Minute, GrantMax: 5 * time.Minute,
		RevokeCooldown: time.Minute, MinRequestInterval: 5 * time.Second, ReconcileInterval: 20 * time.Millisecond}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)}
	e := &env{t: t, clk: clk, k: newFakeKernel(clk), fl: &fakeFlows{}, ev: &fakeEvidence{errs: map[netip.Addr]error{}},
		fs: &fakeFailsafe{}, dhcp: &fakeDHCP{clk: clk, m: map[netip.Addr]model.Binding{}}, logs: &bytes.Buffer{}}
	c, err := New(testConfig(), Deps{Kernel: e.k, Flows: e.fl, Evidence: e.ev, Failsafe: e.fs, Now: clk.Now,
		Log: slog.New(slog.NewTextHandler(&lockedWriter{w: e.logs}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	c.SetBindings(e.dhcp)
	e.c = c
	t.Cleanup(func() {
		e.k.mu.Lock()
		defer e.k.mu.Unlock()
		if len(e.k.violations) > 0 {
			t.Errorf("kernel contract violations: %v", e.k.violations)
		}
	})
	return e
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (e *env) start() {
	e.t.Helper()
	if err := e.c.Start(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) bind(addr netip.Addr, mac model.MAC) model.Binding {
	e.t.Helper()
	b := model.Binding{MAC: mac, Addr: addr, Expires: e.clk.Now().Add(10 * time.Minute)}
	if err := e.dhcp.bind(context.Background(), e.c, b); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func conn(addr netip.Addr) *ipc.GuestConn {
	return &ipc.GuestConn{Local: netip.AddrPortFrom(gateway, 80), Remote: netip.AddrPortFrom(addr, 40000)}
}

func (e *env) guest(op ipc.Op, seconds int, addr netip.Addr) ipc.Response {
	return e.c.GuestHandler().Handle(context.Background(), ipc.Peer{UID: 65534}, ipc.Request{Op: op, DurationSeconds: seconds}, conn(addr))
}

func (e *env) operator(op ipc.Op, target string) ipc.Response {
	return e.c.OperatorHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: op, Target: target}, nil)
}

func state(r ipc.Response) ipc.State {
	if r.Session == nil {
		return ""
	}
	return r.Session.State
}
