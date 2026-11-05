package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/model"
)

func TestNewValidation(t *testing.T) {
	deps := Deps{Kernel: newFakeKernel(&fakeClock{}), Flows: &fakeFlows{}, Evidence: &fakeEvidence{}, Failsafe: &fakeFailsafe{}}
	for name, mutate := range map[string]func(*Config){
		"ipv6 subnet":        func(c *Config) { c.GuestSubnet = netip.MustParsePrefix("fd00::/64") },
		"uncanonical subnet": func(c *Config) { c.GuestSubnet = netip.MustParsePrefix("10.203.0.5/24") },
		"gateway outside":    func(c *Config) { c.Gateway = netip.MustParseAddr("10.9.0.1") },
		"gateway network":    func(c *Config) { c.Gateway = netip.MustParseAddr("10.203.0.0") },
		"max over 15m":       func(c *Config) { c.GrantMax = 16 * time.Minute },
		"max under 30s":      func(c *Config) { c.GrantMax, c.GrantDefault = 29*time.Second, 29*time.Second },
		"default over max":   func(c *Config) { c.GrantDefault = 6 * time.Minute },
		"default fractional": func(c *Config) { c.GrantDefault = 30*time.Second + time.Millisecond },
		"negative cooldown":  func(c *Config) { c.RevokeCooldown = -time.Second },
		"zero reconcile":     func(c *Config) { c.ReconcileInterval = 0 },
		"slow reconcile":     func(c *Config) { c.ReconcileInterval = time.Hour },
		"events":             func(c *Config) { c.MaxEvents = -1 },
	} {
		cfg := testConfig()
		mutate(&cfg)
		if _, err := New(cfg, deps); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := New(testConfig(), Deps{Flows: &fakeFlows{}, Evidence: &fakeEvidence{}}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing kernel accepted: %v", err)
	}
	if _, err := New(testConfig(), Deps{Kernel: deps.Kernel, Flows: deps.Flows, Evidence: deps.Evidence}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing guest-link failsafe accepted: %v", err)
	}
	if _, err := New(testConfig(), deps); err != nil {
		t.Fatal(err)
	}
}

func TestGrantFlushesPreviousHolderFlowsFirst(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	flushedBeforeGrant := false
	e.fl.onFlush = func(addr netip.Addr) {
		if addr == addrA && e.k.count("Grant") == 0 && len(e.c.grants) == 0 {
			flushedBeforeGrant = true
		}
	}
	if r := e.guest(ipc.OpRequest, 60, addrA); !r.OK || state(r) != ipc.StateGranted {
		t.Fatalf("new grant: %+v", r)
	}
	if !flushedBeforeGrant || !e.fl.has(addrA) {
		t.Fatal("new grant was issued before stale conntrack state was flushed")
	}
}

func TestGrantRefusesConntrackFlushFailure(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.fl.fail = errors.New("injected conntrack flush failure")
	if r := e.guest(ipc.OpRequest, 60, addrA); r.OK || r.Error != ipc.ErrUnavailable {
		t.Fatalf("failed conntrack flush granted access: %+v", r)
	}
	if e.k.count("Grant") != 0 || len(e.c.grants) != 0 {
		t.Fatal("controller granted access after pregrant conntrack flush failure")
	}
	e.fl.fail = nil
	if r := e.guest(ipc.OpRequest, 60, addrA); !r.OK || state(r) != ipc.StateGranted {
		t.Fatalf("failed to recover after conntrack flush restored: %+v", r)
	}
}

func TestGrantLifecycleAndKernelExpiry(t *testing.T) {
	e := newEnv(t)
	e.start()
	if r := e.guest(ipc.OpStatus, 0, addrA); !r.OK || state(r) != ipc.StateUnrecognized {
		t.Fatalf("unbound: %+v", r)
	}
	e.bind(addrA, macA)
	if r := e.guest(ipc.OpStatus, 0, addrA); state(r) != ipc.StateDenied || !r.Session.CanRequest {
		t.Fatalf("bound: %+v", r)
	}
	r := e.guest(ipc.OpRequest, 120, addrA)
	if !r.OK || state(r) != ipc.StateGranted || r.Session.RemainingSeconds < 118 || r.Session.GrantedSeconds != 120 {
		t.Fatalf("request: %+v %+v", r, r.Session)
	}
	for range 3 { // duplicates are idempotent
		if r := e.guest(ipc.OpRequest, 0, addrA); !r.OK || state(r) != ipc.StateGranted {
			t.Fatalf("duplicate: %+v", r)
		}
	}
	if n := e.k.count("Grant"); n != 1 {
		t.Fatalf("Grant calls = %d, want 1", n)
	}
	// The kernel alone ends the grant; the controller never re-adds it.
	e.clk.Advance(121 * time.Second)
	if g, d := e.k.grantCounts(); g != 0 || d != 0 {
		t.Fatalf("kernel kept elements after timeout: %d %d", g, d)
	}
	if r := e.guest(ipc.OpStatus, 0, addrA); state(r) != ipc.StateDenied {
		t.Fatalf("after expiry: %+v", r.Session)
	}
	if e.k.count("Grant") != 1 || e.k.count("Revoke") != 0 {
		t.Fatalf("controller wrote on expiry: grant=%d revoke=%d", e.k.count("Grant"), e.k.count("Revoke"))
	}
	if _, ok := e.c.grants[macA]; ok {
		t.Fatal("desired grant survived kernel expiry")
	}
	// Release ends a fresh grant with no cooldown.
	if r := e.guest(ipc.OpRequest, 0, addrA); state(r) != ipc.StateGranted {
		t.Fatalf("re-request: %+v", r)
	}
	if r := e.guest(ipc.OpRelease, 0, addrA); !r.OK || state(r) != ipc.StateDenied {
		t.Fatalf("release: %+v", r)
	}
	if g, d := e.k.grantCounts(); g != 0 || d != 0 || !e.fl.has(addrA) {
		t.Fatalf("release left kernel state %d %d or no flow flush", g, d)
	}
	if r := e.guest(ipc.OpRelease, 0, addrA); !r.OK {
		t.Fatalf("idempotent release: %+v", r)
	}
	// Rate limit since the last successful grant.
	if r := e.guest(ipc.OpRequest, 0, addrA); r.Error != ipc.ErrRateLimited || r.Session.RetryAfterSeconds == 0 {
		t.Fatalf("rate limit: %+v", r)
	}
}

func TestRequestDurationValidation(t *testing.T) {
	for _, tc := range []struct {
		seconds int
		code    ipc.ErrorCode
		granted int
	}{{0, "", 60}, {30, "", 30}, {300, "", 300}, {29, ipc.ErrBadRequest, 0}, {301, ipc.ErrBadRequest, 0}, {-5, ipc.ErrBadRequest, 0}} {
		e := newEnv(t)
		e.start()
		e.bind(addrA, macA)
		r := e.guest(ipc.OpRequest, tc.seconds, addrA)
		if r.Error != tc.code || (tc.granted > 0 && r.Session.GrantedSeconds != tc.granted) {
			t.Errorf("%d: %+v %+v", tc.seconds, r, r.Session)
		}
		if tc.code != "" && e.k.count("Grant") != 0 {
			t.Errorf("%d: rejected request reached the kernel", tc.seconds)
		}
	}
}

func TestGrantTTLBoundedByLease(t *testing.T) {
	e := newEnv(t)
	e.start()
	b := model.Binding{MAC: macA, Addr: addrA, Expires: e.clk.Now().Add(90*time.Second + 500*time.Millisecond)}
	if err := e.dhcp.bind(context.Background(), e.c, b); err != nil {
		t.Fatal(err)
	}
	if r := e.guest(ipc.OpRequest, 300, addrA); r.Session.GrantedSeconds != 90 {
		t.Fatalf("ttl not clamped to lease: %+v", r.Session)
	}
	e.guest(ipc.OpRelease, 0, addrA)
	e.clk.Advance(70 * time.Second)
	if r := e.guest(ipc.OpRequest, 0, addrA); r.Error != ipc.ErrConflict {
		t.Fatalf("short lease: %+v", r)
	}
}

func TestNoGrantWithoutReadback(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.k.dropGrant = true
	r := e.guest(ipc.OpRequest, 0, addrA)
	if r.OK || r.Error != ipc.ErrInternal || state(r) == ipc.StateGranted {
		t.Fatalf("readback-missing reported: %+v", r)
	}
	if len(e.c.grants) != 0 {
		t.Fatal("desired record kept for ineffective grant")
	}
}

func TestGrantFailureLeavesNoRecord(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.k.setFail("Grant", errInjected)
	r := e.guest(ipc.OpRequest, 0, addrA)
	if r.OK || r.Error != ipc.ErrUnavailable {
		t.Fatalf("grant failure: %+v", r)
	}
	if len(e.c.grants) != 0 || e.k.count("Revoke") == 0 {
		t.Fatalf("grant failure left record or skipped cleanup revoke")
	}
	if d, _ := e.c.Degraded(); d {
		t.Fatal("a failed grant with a healthy re-attestation must not degrade")
	}
}

func TestStrayKernelElementsRemoved(t *testing.T) {
	stranger := mustMAC("02:00:00:00:0c:01")
	for _, tc := range []struct {
		name   string
		inject func(e *env)
		viaOp  bool
	}{
		{"untimed granted", func(e *env) { e.k.injectGranted(addrB, macB, 0) }, false},
		{"untimed granted via status", func(e *env) { e.k.injectGranted(addrB, macB, 0) }, true},
		{"over-long granted", func(e *env) { e.k.injectGranted(addrB, macB, 20*time.Minute) }, false},
		{"foreign mac on granted ip", func(e *env) { e.k.injectGranted(addrA, stranger, time.Minute) }, true},
		{"foreign dst", func(e *env) { e.k.injectDst(addrB, time.Minute) }, false},
		{"untimed dst", func(e *env) { e.k.injectDst(addrB, 0) }, true},
		{"extended legit grant", func(e *env) { e.k.injectGranted(addrA, macA, 5*time.Minute) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.start()
			e.bind(addrA, macA)
			e.bind(addrB, macB)
			if r := e.guest(ipc.OpRequest, 60, addrA); state(r) != ipc.StateGranted {
				t.Fatalf("setup grant: %+v", r)
			}
			tc.inject(e)
			if tc.viaOp {
				e.guest(ipc.OpStatus, 0, addrB)
			} else if err := e.c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			e.k.mu.Lock()
			for p, el := range e.k.granted {
				if p != (pair{addrA, macA}) || el.timeout != time.Minute {
					t.Errorf("stray granted element survived: %v %+v", p, el)
				}
			}
			for a, el := range e.k.dst {
				if a != addrA || el.timeout != time.Minute {
					t.Errorf("stray dst element survived: %v %+v", a, el)
				}
			}
			e.k.mu.Unlock()
			// Whatever remains, the guest is reported granted only if both
			// legitimate elements survived.
			r := e.guest(ipc.OpStatus, 0, addrA)
			g, d := e.k.grantCounts()
			if (state(r) == ipc.StateGranted) != (g == 1 && d == 1) {
				t.Errorf("status %s with kernel %d/%d", state(r), g, d)
			}
			if r := e.guest(ipc.OpStatus, 0, addrB); state(r) != ipc.StateDenied {
				t.Errorf("guest B: %+v", r.Session)
			}
		})
	}
}

// observedStartupFailsafe signals each completed Engage call so the failed-
// start retry test need not infer progress from arbitrary sleep durations.
type observedStartupFailsafe struct {
	base     *fakeFailsafe
	attempts chan struct{}
}

func (f observedStartupFailsafe) Engage(ctx context.Context, reason string) error {
	err := f.base.Engage(ctx, reason)
	select {
	case f.attempts <- struct{}{}:
	default:
	}
	return err
}

func TestFailedStartupIsolationKeepsRetryingWithoutAuthority(t *testing.T) {
	e := newEnv(t)
	e.c.cfg.ReconcileInterval = 50 * time.Millisecond
	attempts := make(chan struct{}, 16)
	e.c.failsafe = observedStartupFailsafe{base: e.fs, attempts: attempts}
	e.fs.fail(errInjected)
	e.k.setFail("Attest", errInjected)
	if err := e.c.Start(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatalf("Start unexpectedly succeeded: %v", err)
	}
	// Initial isolation failed. Readback has not confirmed isolation.
	<-attempts
	e.c.mu.Lock()
	initiallyIsolated := e.c.isolated
	e.c.mu.Unlock()
	if initiallyIsolated {
		t.Fatal("initial isolation was incorrectly confirmed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.c.HoldFailedStart(ctx) }()
	wait := func() {
		t.Helper()
		select {
		case <-attempts:
		case <-time.After(2 * time.Second):
			t.Fatal("failed startup stopped attempting isolation")
		}
	}
	assertIsolation := func(want string) {
		t.Helper()
		e.c.mu.Lock()
		confirmed := e.c.isolated
		e.c.mu.Unlock()
		if confirmed != (want == "confirmed") {
			t.Fatalf("isolation confirmed=%v, want %s", confirmed, want)
		}
	}

	e.fs.fail(nil)
	wait()
	assertIsolation("confirmed")
	e.fs.fail(errInjected) // previously confirmed link was reactivated
	wait()
	assertIsolation("unconfirmed")
	e.fs.fail(nil)
	wait()
	assertIsolation("confirmed")

	if err := e.c.Bind(context.Background(), model.Binding{MAC: macA, Addr: addrA, Expires: e.clk.Now().Add(time.Minute)}); !errors.Is(err, ErrDegraded) {
		t.Fatalf("failed startup allowed binding: %v", err)
	}
	if r := e.guest(ipc.OpRequest, 60, addrA); r.OK || r.Error != ipc.ErrUnavailable {
		t.Fatalf("failed startup allowed request: %+v", r)
	}
	if err := e.c.Start(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("failed startup retried Start: %v", err)
	}
	if e.k.count("Grant") != 0 {
		t.Fatal("failed-start safety loop granted authority")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("failed-start loop shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed-start loop did not stop on cancellation")
	}
}

func TestHoldFailedStartRejectsUnfailedController(t *testing.T) {
	e := newEnv(t)
	if err := e.c.HoldFailedStart(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("new controller accepted failed-start supervision: %v", err)
	}
	e.start()
	if err := e.c.HoldFailedStart(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("running controller accepted failed-start supervision: %v", err)
	}
}

// adoptionRaceBindings triggers an Unbind safety transition precisely while
// Start has released the controller mutex to adopt inherited DHCP bindings.
type adoptionRaceBindings struct {
	*fakeDHCP
	onAdopt func(model.Binding)
}

func (b *adoptionRaceBindings) Adopt(binding model.Binding) error {
	if b.onAdopt != nil {
		b.onAdopt(binding)
	}
	return b.fakeDHCP.Adopt(binding)
}

func TestStartAdoptionSafetyRaceNeverReturnsSuccess(t *testing.T) {
	e := newEnv(t)
	e.k.injectBound(addrA, macA, 10*time.Minute)
	e.k.setFail("Revoke", errInjected)
	b := &adoptionRaceBindings{fakeDHCP: e.dhcp}
	b.onAdopt = func(binding model.Binding) {
		e.c.Unbind(context.Background(), binding, "concurrent failed revoke")
	}
	e.c.SetBindings(b)
	if err := e.c.Start(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatalf("Start returned success after degradation during adoption: %v", err)
	}
	if d, reason := e.c.Degraded(); !d || reason == "" {
		t.Fatalf("lost degraded status: degraded=%v reason=%q", d, reason)
	}
	if err := e.c.Run(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("running a failed-start controller: %v", err)
	}
	if e.k.count("Grant") != 0 || e.fs.count() == 0 {
		t.Fatal("failed-start adoption granted authority or skipped isolation")
	}
}

func TestStartAdoptionCancellationDoesNotServe(t *testing.T) {
	e := newEnv(t)
	e.k.injectBound(addrA, macA, 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	b := &adoptionRaceBindings{fakeDHCP: e.dhcp}
	b.onAdopt = func(model.Binding) { cancel() }
	e.c.SetBindings(b)
	if err := e.c.Start(ctx); !errors.Is(err, ErrDegraded) {
		t.Fatalf("canceled adoption accepted: %v", err)
	}
	if err := e.c.Run(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("canceled controller entered serving state: %v", err)
	}
	if d, _ := e.c.Degraded(); !d {
		t.Fatal("canceled startup did not fail closed")
	}
}

func TestStartFailureRefusesEverything(t *testing.T) {
	e := newEnv(t)
	e.k.setFail("Attest", errInjected)
	if err := e.c.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded without attestation")
	}
	if err := e.c.Start(context.Background()); err == nil {
		t.Fatal("second Start accepted")
	}
	if d, _ := e.c.Degraded(); !d || e.fs.count() != 1 {
		t.Fatalf("degraded=%v failsafe=%d", d, e.fs.count())
	}
	b := model.Binding{MAC: macA, Addr: addrA, Expires: e.clk.Now().Add(time.Hour)}
	if err := e.c.Bind(context.Background(), b); err == nil {
		t.Fatal("Bind accepted before a successful Start")
	}
	for _, op := range []ipc.Op{ipc.OpStatus, ipc.OpRequest, ipc.OpRelease} {
		if r := e.guest(op, 0, addrA); r.OK || r.Error != ipc.ErrUnavailable {
			t.Errorf("%s: %+v", op, r)
		}
	}
	for _, op := range []ipc.Op{ipc.OpSnapshot, ipc.OpReset} {
		if r := e.operator(op, ""); r.OK {
			t.Errorf("%s accepted", op)
		}
	}
	if err := e.c.Run(context.Background()); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Run: %v", err)
	}
	if e.k.count("Grant") != 0 {
		t.Fatal("grant issued")
	}
}

func TestReconcileAttestFailureDegrades(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	if r := e.guest(ipc.OpRequest, 0, addrA); state(r) != ipc.StateGranted {
		t.Fatal("setup")
	}
	flushes := e.k.count("FlushGrants")
	e.k.setFail("Attest", errInjected)
	for range 2 {
		if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if d, reason := e.c.Degraded(); !d || reason == "" {
		t.Fatal("not degraded")
	}
	if e.k.count("FlushGrants") != flushes+1 || e.fs.count() != 2 {
		t.Fatalf("flush=%d failsafe=%d", e.k.count("FlushGrants")-flushes, e.fs.count())
	}
	if g, d := e.k.grantCounts(); g+d != 0 || !e.fl.has(addrA) {
		t.Fatal("grants not flushed on degrade")
	}
	e.k.setFail("Attest", nil) // never auto-recovers
	if r := e.guest(ipc.OpRequest, 0, addrA); r.Error != ipc.ErrUnavailable || state(r) != ipc.StateUnavailable {
		t.Fatalf("request while degraded: %+v", r)
	}
	if err := e.dhcp.bind(context.Background(), e.c, model.Binding{MAC: macB, Addr: addrB, Expires: e.clk.Now().Add(time.Hour)}); !errors.Is(err, ErrDegraded) {
		t.Fatalf("bind while degraded: %v", err)
	}
	if r := e.operator(ipc.OpSnapshot, ""); !r.OK || r.Snapshot.Enforcement != "degraded" {
		t.Fatalf("snapshot: %+v", r)
	}
}

func TestDegradedIsolationRetriesAndDetectsLoss(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.fs.fail(errInjected)
	e.k.setFail("Attest", errInjected)
	if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatal(err)
	}
	assertIsolation := func(want string, attempts int) {
		t.Helper()
		if e.fs.count() != attempts {
			t.Fatalf("isolation attempts: got %d want %d", e.fs.count(), attempts)
		}
		resp := e.operator(ipc.OpSnapshot, "")
		if !resp.OK || resp.Snapshot.Isolation != want {
			t.Fatalf("isolation snapshot: got %+v want %s", resp, want)
		}
	}
	assertIsolation("unconfirmed", 1)
	e.fs.fail(nil)
	if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatal(err)
	}
	assertIsolation("confirmed", 2)
	// Even after success, a later failed reassertion must clear confirmation.
	// This detects an interface that could have been brought back UP.
	e.fs.fail(errInjected)
	if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatal(err)
	}
	assertIsolation("unconfirmed", 3)
	e.fs.fail(nil)
	if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatal(err)
	}
	assertIsolation("confirmed", 4)
}

func TestSnapshotFailureInStatusDegrades(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.k.setFail("Snapshot", errInjected)
	if r := e.guest(ipc.OpStatus, 0, addrA); r.Error != ipc.ErrUnavailable {
		t.Fatalf("status: %+v", r)
	}
	if d, _ := e.c.Degraded(); !d || e.fs.count() != 1 {
		t.Fatal("snapshot failure did not degrade")
	}
}

func TestCancelledContextDoesNotDegrade(t *testing.T) {
	e := newEnv(t)
	e.start()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.k.setFail("Attest", context.Canceled)
	if err := e.c.Reconcile(ctx); err == nil {
		t.Fatal("expected error")
	}
	if d, _ := e.c.Degraded(); d {
		t.Fatal("cancellation tripped the failsafe")
	}
}

func TestRestartRevokesInheritedAndAdoptsBindings(t *testing.T) {
	e := newEnv(t)
	e.k.injectGranted(addrA, macA, 5*time.Minute)
	e.k.injectDst(addrA, 5*time.Minute)
	e.k.injectGranted(addrB, macB, 0) // untimed hostile grant
	e.k.injectBound(addrA, macA, 10*time.Minute)
	stranger := mustMAC("02:00:00:00:0c:01")
	addrC := netip.MustParseAddr("10.203.0.102")
	e.k.injectBound(addrC, stranger, 0) // untimed bound: deleted, not adopted
	e.start()
	if g, d := e.k.grantCounts(); g+d != 0 {
		t.Fatalf("inherited grants survived restart: %d %d", g, d)
	}
	if !e.fl.has(addrA) || !e.fl.has(addrB) {
		t.Fatal("flows not flushed for inherited grants")
	}
	if len(e.dhcp.adopted) != 1 || e.dhcp.adopted[0].Addr != addrA || e.dhcp.adopted[0].MAC != macA {
		t.Fatalf("adopted: %+v", e.dhcp.adopted)
	}
	if e.k.hasBound(addrC, stranger) {
		t.Fatal("untimed bound element kept")
	}
	if r := e.guest(ipc.OpStatus, 0, addrA); state(r) != ipc.StateDenied {
		t.Fatalf("adopted guest: %+v", r.Session)
	}
	if r := e.guest(ipc.OpRequest, 0, addrA); state(r) != ipc.StateGranted {
		t.Fatalf("adopted guest grant: %+v", r)
	}
}

func TestOperatorRevokeCooldownAndReset(t *testing.T) {
	e := newEnv(t)
	e.start()
	b := e.bind(addrA, macA)
	e.guest(ipc.OpRequest, 0, addrA)
	if r := e.operator(ipc.OpRevoke, macA.String()); !r.OK {
		t.Fatalf("revoke: %+v", r)
	}
	if g, d := e.k.grantCounts(); g+d != 0 || !e.fl.has(addrA) {
		t.Fatal("revoke left kernel state")
	}
	r := e.guest(ipc.OpStatus, 0, addrA)
	if state(r) != ipc.StateRevoked || r.Session.RetryAfterSeconds <= 0 {
		t.Fatalf("status: %+v", r.Session)
	}
	// DHCP renewal / reconnect does not clear the cooldown.
	e.dhcp.release(context.Background(), e.c, b)
	e.bind(addrA, macA)
	e.clk.Advance(10 * time.Second)
	if r := e.guest(ipc.OpRequest, 0, addrA); r.Error != ipc.ErrForbidden {
		t.Fatalf("request in cooldown: %+v", r)
	}
	if r := e.operator(ipc.OpReset, ""); !r.OK {
		t.Fatalf("reset: %+v", r)
	}
	if r := e.guest(ipc.OpRequest, 0, addrA); state(r) != ipc.StateGranted {
		t.Fatalf("request after reset: %+v", r)
	}
	if r := e.operator(ipc.OpRevoke, "ff:ff:ff:ff:ff:ff"); r.Error != ipc.ErrBadRequest {
		t.Fatalf("bad target: %+v", r)
	}
	// Reset revokes live grants too.
	if r := e.operator(ipc.OpReset, ""); !r.OK {
		t.Fatal("reset")
	}
	if g, d := e.k.grantCounts(); g+d != 0 {
		t.Fatal("reset left grants")
	}
}

func TestUnbindRevokesGrant(t *testing.T) {
	e := newEnv(t)
	e.start()
	b := e.bind(addrA, macA)
	e.guest(ipc.OpRequest, 0, addrA)
	e.dhcp.release(context.Background(), e.c, b)
	if g, d := e.k.grantCounts(); g+d != 0 || !e.fl.has(addrA) || e.k.hasBound(addrA, macA) {
		t.Fatal("unbind left authority")
	}
	if r := e.guest(ipc.OpStatus, 0, addrA); state(r) != ipc.StateUnrecognized {
		t.Fatalf("after release: %+v", r.Session)
	}
}

func TestIdentityRejections(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.ev.errs[addrA] = fmt.Errorf("%w: arp says 02:00:00:00:0c:01", errors.New("neighbour MAC differs"))
	r := e.guest(ipc.OpRequest, 0, addrA)
	if r.Error != ipc.ErrIdentity || state(r) != ipc.StateAmbiguous || strings.Contains(r.Session.Reason, "0c:01") {
		t.Fatalf("ambiguous: %+v %+v", r, r.Session)
	}
	if e.k.count("Grant") != 0 {
		t.Fatal("ambiguous evidence granted")
	}
	for _, a := range []string{"10.9.0.5", "10.203.0.1", "10.203.0.255", "10.203.0.0"} {
		if r := e.guest(ipc.OpRequest, 0, netip.MustParseAddr(a)); r.Error != ipc.ErrIdentity || state(r) != ipc.StateUnrecognized {
			t.Errorf("%s: %+v", a, r)
		}
	}
	wrongLocal := &ipc.GuestConn{Local: netip.MustParseAddrPort("10.203.0.2:80"), Remote: netip.AddrPortFrom(addrA, 1)}
	if r := e.c.GuestHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: ipc.OpRequest}, wrongLocal); r.Error != ipc.ErrIdentity {
		t.Errorf("wrong local: %+v", r)
	}
	if r := e.c.GuestHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: ipc.OpStatus}, nil); r.Error != ipc.ErrForbidden {
		t.Errorf("nil guest: %+v", r)
	}
	if r := e.c.GuestHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: ipc.OpReset}, conn(addrA)); r.Error != ipc.ErrForbidden {
		t.Errorf("operator op on guest socket: %+v", r)
	}
	if r := e.c.OperatorHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: ipc.OpSnapshot}, conn(addrA)); r.Error != ipc.ErrForbidden {
		t.Errorf("guest conn on operator socket: %+v", r)
	}
	if r := e.c.OperatorHandler().Handle(context.Background(), ipc.Peer{}, ipc.Request{Op: ipc.OpStatus}, nil); r.Error != ipc.ErrForbidden {
		t.Errorf("guest op on operator socket: %+v", r)
	}
}

func TestConcurrentRequestsExactlyOneGrant(t *testing.T) {
	e := newEnv(t)
	e.start()
	const guests = 32
	addrs := make([]netip.Addr, guests)
	for i := range guests {
		addrs[i] = netip.AddrFrom4([4]byte{10, 203, 0, byte(100 + i)})
		e.bind(addrs[i], model.MAC{0x02, 0, 0, 0, 0x10, byte(i)})
	}
	var wg sync.WaitGroup
	for i := range 64 { // 64 from guest 0, plus 4 each from all 32 guests
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.guest(ipc.OpRequest, 0, addrs[0]); state(r) != ipc.StateGranted {
				t.Errorf("guest 0 request %d: %+v", i, r)
			}
		}()
	}
	for i := range guests * 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.guest(ipc.OpRequest, 0, addrs[i%guests]); state(r) != ipc.StateGranted {
				t.Errorf("guest %d: %+v", i%guests, r)
			}
		}()
	}
	// Concurrent DHCP activity holding the DHCP lock while calling the sink
	// must not deadlock against guest operations.
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := model.Binding{MAC: model.MAC{0x02, 0, 0, 0, 0x20, byte(i)}, Addr: netip.AddrFrom4([4]byte{10, 203, 0, byte(180 + i)}), Expires: e.clk.Now().Add(time.Hour)}
			_ = e.dhcp.bind(context.Background(), e.c, b)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock")
	}
	if n := e.k.count("Grant"); n != guests {
		t.Fatalf("Grant calls = %d, want %d", n, guests)
	}
	if g, d := e.k.grantCounts(); g != guests || d != guests {
		t.Fatalf("kernel elements %d/%d", g, d)
	}
}

func TestSnapshotNeverLeaksLeaseIDs(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	e.bind(addrB, macB)
	e.guest(ipc.OpRequest, 0, addrA)
	e.guest(ipc.OpRequest, 0, addrB)
	if err := e.c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := e.operator(ipc.OpSnapshot, "")
	if !r.OK || len(r.Snapshot.Grants) != 2 || !r.Snapshot.Grants[0].KernelPresent || len(r.Snapshot.Counters) == 0 {
		t.Fatalf("snapshot: %+v", r.Snapshot)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	e.c.mu.Lock()
	ids := []string{e.c.grants[macA].leaseID, e.c.grants[macB].leaseID}
	e.c.mu.Unlock()
	logs := e.logs.String()
	for _, id := range ids {
		if strings.Contains(string(data), id) || strings.Contains(logs, id) {
			t.Fatal("lease ID leaked")
		}
	}
	if regexp.MustCompile(`[0-9a-f]{32}`).Match(data) {
		t.Fatal("32-hex identifier in snapshot")
	}
}

func TestRunReconcilesAndStops(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.k.injectGranted(addrB, macB, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.c.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if g, _ := e.k.grantCounts(); g == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not remove the stray element")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d, _ := e.c.Degraded(); d {
		t.Fatal("orderly stop degraded the controller")
	}
}

func TestReconcileBoundElements(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.bind(addrA, macA)
	stranger := mustMAC("02:00:00:00:0c:01")
	e.k.injectBound(addrB, stranger, 0)
	e.k.mu.Lock()
	delete(e.k.bound, pair{addrA, macA}) // lost bound element for a live binding
	e.k.mu.Unlock()
	if err := e.c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.k.hasBound(addrB, stranger) || !e.k.hasBound(addrA, macA) {
		t.Fatal("bound elements not converged")
	}
}

// A missing guard is already unsafe: cleanup must not delay link isolation
// or exhaust the context subsequently passed to the failsafe.
type orderingFailsafe struct {
	k      *fakeKernel
	before int
	t      *testing.T
}

func (f orderingFailsafe) Engage(ctx context.Context, _ string) error {
	if ctx.Err() != nil {
		f.t.Fatal("failsafe received exhausted cleanup context")
	}
	if f.k.count("FlushGrants") != f.before {
		f.t.Fatal("cleanup ran before isolation")
	}
	return nil
}
func TestDegradedIsolatesBeforeFailingCleanup(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.c.failsafe = orderingFailsafe{k: e.k, before: e.k.count("FlushGrants"), t: t}
	e.k.setFail("Attest", errInjected)
	e.k.setFail("FlushGrants", errInjected)
	if err := e.c.Reconcile(context.Background()); !errors.Is(err, ErrDegraded) {
		t.Fatal(err)
	}
}
