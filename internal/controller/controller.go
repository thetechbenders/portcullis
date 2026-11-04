// Package controller is the privileged Portcullis authorization state
// machine. It decides grants only from kernel-observed evidence (the guest
// TCP connection passed over SCM_RIGHTS, the controller's own DHCP binding
// table and the kernel neighbour table), reports a grant only after reading
// it back from the attested kernel guard, removes any kernel grant element it
// did not issue, and fails closed: once attestation fails it flushes grants,
// engages the failsafe and refuses every later request until restart.
//
// Locking: one mutex (mu) serializes all controller state and every kernel
// mutation. The DHCP server calls Bind/Unbind while holding its own lock, so
// the controller NEVER calls into Bindings while holding mu (lock order is
// always DHCP → controller). Binding reads happen before mu is taken and are
// validated with a change sequence number bumped by every Bind/Unbind.
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/lease"
	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	// ErrConfig rejects an invalid Config or missing dependency.
	ErrConfig = errors.New("invalid controller configuration")
	// ErrNotStarted refuses work before a successful Start (or after a failed one).
	ErrNotStarted = errors.New("controller is not running")
	// ErrDegraded refuses work after enforcement could not be verified.
	ErrDegraded = errors.New("enforcement degraded; restart required")
	// ErrBinding rejects a DHCP binding the controller will not install.
	ErrBinding = errors.New("invalid DHCP binding")
)

const (
	minGrant            = 30 * time.Second
	maxBindTTL          = 2 * time.Hour
	kernelSlack         = 2 * time.Second
	cleanupTimeout      = 10 * time.Second
	defaultMaxEvents    = 256
	bindingReadAttempts = 4
)

// Kernel is the attested persistent guard. Every method is one bounded
// kernel transaction; any Attest/Snapshot error means enforcement is unsafe.
type Kernel interface {
	Attest(ctx context.Context) (model.KernelState, error)
	Snapshot(ctx context.Context) (model.KernelState, error)
	Bind(ctx context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error
	Unbind(ctx context.Context, ip netip.Addr, mac model.MAC) error
	Grant(ctx context.Context, ip netip.Addr, mac model.MAC, ttl time.Duration) error
	Revoke(ctx context.Context, ip netip.Addr, mac model.MAC) error
	RevokeDst(ctx context.Context, ip netip.Addr) error
	FlushGrants(ctx context.Context) error
}

// Flows deletes conntrack state for an address in both directions.
type Flows interface {
	Flush(ctx context.Context, ip netip.Addr) error
}

// Bindings is the controller's own DHCP server.
type Bindings interface {
	Lookup(netip.Addr) (model.Binding, bool)
	Bindings() []model.Binding
	Adopt(model.Binding) error
}

// Evidence cross-checks a binding against kernel neighbour state.
type Evidence interface {
	Corroborate(addr netip.Addr, b model.Binding) error
}

// Failsafe isolates guests when the guard cannot be attested.
type Failsafe interface {
	Engage(ctx context.Context, reason string) error
}

// Config bounds the controller's policy.
type Config struct {
	GuestSubnet        netip.Prefix
	Gateway            netip.Addr
	GrantDefault       time.Duration
	GrantMax           time.Duration
	RevokeCooldown     time.Duration
	MinRequestInterval time.Duration
	ReconcileInterval  time.Duration
	MaxEvents          int
}

// Deps are the injected collaborators. Failsafe may be nil.
type Deps struct {
	Kernel   Kernel
	Flows    Flows
	Evidence Evidence
	Failsafe Failsafe
	Now      func() time.Time
	Log      *slog.Logger
}

type phase int

const (
	phaseNew phase = iota
	phaseStarting
	phaseRunning
	phaseFailed
)

type pair struct {
	addr netip.Addr
	mac  model.MAC
}

// grant is a desired grant. leaseID is a bearer secret of the lease store
// and is never placed in events, logs or snapshots.
type grant struct {
	leaseID string
	addr    netip.Addr
	mac     model.MAC
	ttl     time.Duration
	expires time.Time
}

// Controller is the authorization state machine.
type Controller struct {
	cfg      Config
	kernel   Kernel
	flows    Flows
	evidence Evidence
	failsafe Failsafe
	now      func() time.Time
	log      *slog.Logger

	mu         sync.Mutex
	bindings   Bindings
	phase      phase
	degraded   bool
	reason     string
	bindSeq    uint64
	store      *lease.Store
	grants     map[model.MAC]*grant
	cooldown   map[model.MAC]time.Time
	lastGrant  map[model.MAC]time.Time
	events     []ipc.EventView
	evNext     int
	last       model.KernelState
	lastRead   time.Time
	lastAttest time.Time
}

// New validates cfg and deps. The controller is unusable until Start.
func New(cfg Config, deps Deps) (*Controller, error) {
	bad := func(msg string) error { return fmt.Errorf("%w: %s", ErrConfig, msg) }
	p := cfg.GuestSubnet
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 16 || p.Bits() > 30 {
		return nil, bad("guest subnet must be a canonical IPv4 prefix between /16 and /30")
	}
	if !cfg.Gateway.Is4() || !p.Contains(cfg.Gateway) || cfg.Gateway == p.Addr() || cfg.Gateway == lastAddr(p) {
		return nil, bad("gateway must be a host address inside the guest subnet")
	}
	if cfg.GrantMax < minGrant || cfg.GrantMax > lease.MaxDuration || cfg.GrantMax%time.Second != 0 {
		return nil, bad("grant max must be whole seconds between 30s and 15m")
	}
	if cfg.GrantDefault < minGrant || cfg.GrantDefault > cfg.GrantMax || cfg.GrantDefault%time.Second != 0 {
		return nil, bad("grant default must be whole seconds between 30s and grant max")
	}
	if cfg.RevokeCooldown < 0 || cfg.RevokeCooldown > 24*time.Hour {
		return nil, bad("revoke cooldown must be between 0 and 24h")
	}
	if cfg.MinRequestInterval < 0 || cfg.MinRequestInterval > time.Hour {
		return nil, bad("minimum request interval must be between 0 and 1h")
	}
	if cfg.ReconcileInterval < 10*time.Millisecond || cfg.ReconcileInterval > 30*time.Second {
		return nil, bad("reconcile interval must be between 10ms and 30s")
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = defaultMaxEvents
	}
	if cfg.MaxEvents < 1 || cfg.MaxEvents > 4096 {
		return nil, bad("max events must be between 1 and 4096")
	}
	if deps.Kernel == nil || deps.Flows == nil || deps.Evidence == nil {
		return nil, bad("kernel, flows and evidence dependencies are required")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.New(slog.DiscardHandler)
	}
	return &Controller{
		cfg: cfg, kernel: deps.Kernel, flows: deps.Flows, evidence: deps.Evidence,
		failsafe: deps.Failsafe, now: deps.Now, log: deps.Log,
		store:     lease.NewStore(deps.Now),
		grants:    map[model.MAC]*grant{},
		cooldown:  map[model.MAC]time.Time{},
		lastGrant: map[model.MAC]time.Time{},
	}, nil
}

// SetBindings wires the DHCP server. It must be called before Start and is
// ignored afterwards: the binding source never changes at runtime.
func (c *Controller) SetBindings(b Bindings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseNew {
		c.log.Error("SetBindings after Start ignored")
		return
	}
	c.bindings = b
}

// Degraded reports whether enforcement is degraded (or Start failed).
func (c *Controller) Degraded() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.degraded, c.reason
}

// Start attests the guard, revokes every inherited grant, confirms the grant
// sets are empty and adopts valid timed bound elements into the DHCP table.
// Any failure leaves the controller permanently unusable and degraded (grants
// flushed, failsafe engaged): an unattested guard must not serve guests.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.phase != phaseNew {
		c.mu.Unlock()
		return fmt.Errorf("%w: Start already attempted", ErrNotStarted)
	}
	if c.bindings == nil {
		c.mu.Unlock()
		return fmt.Errorf("%w: SetBindings was not called", ErrConfig)
	}
	c.phase = phaseStarting
	adopt, err := c.startLocked(ctx)
	if err != nil {
		c.phase = phaseFailed
		c.degradeLocked("start: " + err.Error())
		c.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrDegraded, err)
	}
	bs := c.bindings
	c.mu.Unlock()

	// Adopt calls into the DHCP server, so mu must not be held.
	var rejected []model.Binding
	for _, b := range adopt {
		if err := bs.Adopt(b); err != nil {
			rejected = append(rejected, b)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range rejected {
		c.unbindKernelLocked(b.Addr, b.MAC, "adoption rejected by DHCP")
	}
	c.phase = phaseRunning
	c.eventLocked("started", fmt.Sprintf("adopted %d bindings", len(adopt)-len(rejected)))
	return nil
}

func (c *Controller) startLocked(ctx context.Context) ([]model.Binding, error) {
	ks, err := c.kernel.Attest(ctx)
	if err != nil {
		return nil, fmt.Errorf("initial attestation failed: %w", err)
	}
	now := c.now()
	c.last, c.lastRead, c.lastAttest = ks, now, now

	// A restart never inherits authority.
	inherited := map[netip.Addr]bool{}
	for _, e := range ks.Granted {
		inherited[e.Addr] = true
	}
	for _, e := range ks.GrantedDst {
		inherited[e.Addr] = true
	}
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.kernel.FlushGrants(cctx); err != nil {
		return nil, fmt.Errorf("revoking inherited grants: %w", err)
	}
	for _, a := range sortedAddrs(inherited) {
		c.flushFlowsLocked(a)
	}
	c.eventLocked("inherited-grants-revoked", fmt.Sprintf("%d addresses", len(inherited)))

	ks, err = c.kernel.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation after grant flush failed: %w", err)
	}
	if len(ks.Granted)+len(ks.GrantedDst) != 0 {
		return nil, errors.New("grant sets not empty after flush")
	}
	c.last, c.lastRead = ks, c.now()

	addrs, macs := map[netip.Addr]int{}, map[model.MAC]int{}
	for _, e := range ks.Bound {
		addrs[e.Addr]++
		macs[e.MAC]++
	}
	var adopt []model.Binding
	for _, e := range ks.Bound {
		ok := e.Timeout > 0 && e.Timeout <= maxBindTTL+kernelSlack && e.Expires >= time.Second &&
			e.Expires <= e.Timeout && c.hostAddr(e.Addr) && validMAC(e.MAC) &&
			addrs[e.Addr] == 1 && macs[e.MAC] == 1
		if ok {
			adopt = append(adopt, model.Binding{MAC: e.MAC, Addr: e.Addr, Expires: now.Add(e.Expires)})
			continue
		}
		c.unbindKernelLocked(e.Addr, e.MAC, "untimed, duplicate or invalid bound element")
	}
	return adopt, nil
}

// Run reconciles every ReconcileInterval until ctx is done. A degraded
// controller keeps running (so operators can see why) but does nothing.
func (c *Controller) Run(ctx context.Context) error {
	c.mu.Lock()
	running := c.phase == phaseRunning
	c.mu.Unlock()
	if !running {
		return ErrNotStarted
	}
	t := time.NewTicker(c.cfg.ReconcileInterval)
	defer t.Stop()
	logged := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			err := c.Reconcile(ctx)
			if err == nil || ctx.Err() != nil {
				continue
			}
			if errors.Is(err, ErrDegraded) {
				if !logged {
					c.log.Error("controller degraded; refusing all grants until restart", "err", err)
					logged = true
				}
				continue
			}
			c.log.Warn("reconcile failed", "err", err)
		}
	}
}

// Reconcile re-attests the guard, removes stray, untimed or over-long
// kernel elements, ends desired grants whose elements vanished (never
// re-adding them) and converges bound elements with live DHCP bindings.
func (c *Controller) Reconcile(ctx context.Context) error {
	var list []model.Binding
	consistent, err := c.lockAfterRead(func(bs Bindings) { list = bs.Bindings() })
	defer c.mu.Unlock()
	if err != nil {
		return err
	}
	ks, err := c.readKernelLocked(ctx, true, false)
	if err != nil {
		return err
	}
	c.pruneLocked()
	if !consistent {
		// Bindings changed concurrently; converge bound elements next round.
		return nil
	}
	return c.reconcileBoundLocked(ctx, ks, list)
}

func (c *Controller) reconcileBoundLocked(ctx context.Context, ks model.KernelState, list []model.Binding) error {
	now := c.now()
	live := map[pair]model.Binding{}
	for _, b := range list {
		if c.hostAddr(b.Addr) && validMAC(b.MAC) && now.Before(b.Expires) {
			live[pair{b.Addr, b.MAC}] = b
		}
	}
	for _, g := range c.sortedGrantsLocked() {
		if _, ok := live[pair{g.addr, g.mac}]; !ok {
			if err := c.endGrantLocked(g, "binding-ended", nil); err != nil {
				return err
			}
		}
	}
	present := map[pair]bool{}
	for _, e := range ks.Bound {
		p := pair{e.Addr, e.MAC}
		if b, ok := live[p]; ok && !present[p] && e.Timeout > 0 && e.Timeout <= maxBindTTL+kernelSlack &&
			e.Expires <= e.Timeout && e.Expires <= b.Expires.Sub(now)+kernelSlack {
			present[p] = true
			continue
		}
		c.unbindKernelLocked(e.Addr, e.MAC, "untimed, over-long or unbound element")
	}
	for _, b := range list {
		p := pair{b.Addr, b.MAC}
		if _, ok := live[p]; !ok || present[p] {
			continue
		}
		ttl := min(b.Expires.Sub(now).Truncate(time.Second), maxBindTTL)
		if ttl < time.Second {
			continue
		}
		if err := c.kernel.Bind(ctx, b.Addr, b.MAC, ttl); err != nil {
			c.eventLocked("bind-failed", fmt.Sprintf("address %s mac %s", b.Addr, b.MAC))
			continue
		}
		c.eventLocked("bound-restored", fmt.Sprintf("address %s mac %s seconds %d", b.Addr, b.MAC, int(ttl/time.Second)))
	}
	return nil
}

// Bind implements the DHCP sink: it installs the anti-spoofing element
// before the DHCP server may ACK. It refuses unless running and attested.
func (c *Controller) Bind(ctx context.Context, b model.Binding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.readyLocked(); err != nil {
		return err
	}
	if !c.hostAddr(b.Addr) || !validMAC(b.MAC) {
		return ErrBinding
	}
	rem := b.Expires.Sub(c.now())
	if rem <= 0 {
		return fmt.Errorf("%w: binding already expired", ErrBinding)
	}
	ttl := max(min(rem.Truncate(time.Second), maxBindTTL), time.Second)
	c.bindSeq++
	// A grant belongs to exactly one (address, MAC) binding.
	for _, g := range c.sortedGrantsLocked() {
		if (g.mac == b.MAC) != (g.addr == b.Addr) {
			if err := c.endGrantLocked(g, "binding-changed", nil); err != nil {
				return err
			}
		}
	}
	if err := c.kernel.Bind(ctx, b.Addr, b.MAC, ttl); err != nil {
		return fmt.Errorf("kernel bind: %w", err)
	}
	c.eventLocked("bind", fmt.Sprintf("address %s mac %s seconds %d", b.Addr, b.MAC, int(ttl/time.Second)))
	return nil
}

// Unbind implements the DHCP sink: it removes every grant derived from the
// address or MAC (kernel and conntrack) and the bound element. It always
// acts, even when degraded or not started, because it only removes authority.
func (c *Controller) Unbind(ctx context.Context, b model.Binding, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bindSeq++
	if !b.Addr.Is4() || !validMAC(b.MAC) {
		c.log.Warn("unbind of invalid binding ignored")
		return
	}
	reason = sanitize(reason, 64)
	for _, g := range c.sortedGrantsLocked() {
		if g.mac == b.MAC || g.addr == b.Addr {
			_ = c.endGrantLocked(g, "binding-ended: "+reason, nil)
		}
	}
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.kernel.Revoke(cctx, b.Addr, b.MAC); err != nil {
		c.degradeLocked("revoking grant on unbind failed: " + err.Error())
	}
	c.flushFlowsLocked(b.Addr)
	c.unbindKernelLocked(b.Addr, b.MAC, reason)
	c.eventLocked("unbind", fmt.Sprintf("address %s mac %s reason %s", b.Addr, b.MAC, reason))
}

// lockAfterRead runs read against the DHCP table without holding mu, then
// returns with mu HELD. consistent is false if a Bind/Unbind raced the read.
func (c *Controller) lockAfterRead(read func(Bindings)) (consistent bool, err error) {
	for range bindingReadAttempts {
		c.mu.Lock()
		if err := c.readyLocked(); err != nil {
			return false, err
		}
		seq, bs := c.bindSeq, c.bindings
		c.mu.Unlock()
		read(bs)
		c.mu.Lock()
		if c.bindSeq == seq {
			return true, c.readyLocked()
		}
		c.mu.Unlock()
	}
	c.mu.Lock()
	return false, c.readyLocked()
}

func (c *Controller) readyLocked() error {
	if c.degraded {
		return fmt.Errorf("%w: %s", ErrDegraded, c.reason)
	}
	if c.phase != phaseRunning {
		return ErrNotStarted
	}
	return nil
}

// readKernelLocked reads kernel truth and enforces grant consistency on it.
// A failure degrades the controller unless it is explained by cancellation
// of the caller's context (mustSucceed=false): a slow or abandoned guest
// request must not be able to trip the failsafe. The reconcile loop is the
// backstop for genuinely hung kernel commands.
func (c *Controller) readKernelLocked(ctx context.Context, full, mustSucceed bool) (model.KernelState, error) {
	var ks model.KernelState
	var err error
	if full {
		ks, err = c.kernel.Attest(ctx)
	} else {
		ks, err = c.kernel.Snapshot(ctx)
	}
	if err != nil {
		if !mustSucceed && ctx.Err() != nil {
			return ks, ctx.Err()
		}
		c.degradeLocked("attestation failed: " + err.Error())
		return ks, fmt.Errorf("%w: %v", ErrDegraded, err)
	}
	now := c.now()
	c.last, c.lastRead = ks, now
	if full {
		c.lastAttest = now
	}
	return ks, c.enforceGrantsLocked(ks)
}

// degradeLocked enters the terminal fail-closed state once: flush every
// grant, flush flows, clear desired grants, engage the failsafe.
func (c *Controller) degradeLocked(reason string) {
	if c.degraded {
		return
	}
	c.degraded = true
	c.reason = sanitize(reason, 256)
	c.log.Error("enforcement degraded", "reason", c.reason)
	c.eventLocked("degraded", c.reason)
	// Isolate before attempting cleanup: an absent/dormant guard cannot
	// protect packets while nft or conntrack cleanup is slow or failing.
	// Its deadline is independent of all later cleanup operations.
	if c.failsafe != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := c.failsafe.Engage(ctx, c.reason)
		cancel()
		if err != nil {
			c.eventLocked("failsafe-failed", sanitize(err.Error(), 128))
		} else {
			c.eventLocked("failsafe", "guest isolation engaged")
		}
	}
	addrs := map[netip.Addr]bool{}
	for _, g := range c.grants {
		addrs[g.addr] = true
		c.store.Revoke(g.leaseID)
	}
	clear(c.grants)
	for _, e := range c.last.Granted {
		addrs[e.Addr] = true
	}
	for _, e := range c.last.GrantedDst {
		addrs[e.Addr] = true
	}
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.kernel.FlushGrants(cctx); err != nil {
		c.eventLocked("flush-failed", sanitize(err.Error(), 128))
	}
	for _, a := range sortedAddrs(addrs) {
		c.flushFlowsLocked(a)
	}
}

// enforceGrantsLocked makes the desired grants and the kernel grant sets
// agree by REMOVING authority only: expired desired grants end, kernel
// elements that are untimed, over-long, foreign or longer-lived than the
// desired grant are revoked, and desired grants whose elements are missing
// end. A failed removal degrades the controller.
func (c *Controller) enforceGrantsLocked(ks model.KernelState) error {
	now := c.now()
	view := newView(ks)
	for _, g := range c.sortedGrantsLocked() {
		if !c.liveLocked(g, now) {
			if err := c.endGrantLocked(g, "expired", view); err != nil {
				return err
			}
		}
	}
	for _, e := range ks.Granted {
		if _, ok := view.granted[pair{e.Addr, e.MAC}]; !ok {
			continue
		}
		if g := c.grants[e.MAC]; g != nil && g.addr == e.Addr && c.timeoutOK(e, g, now) {
			continue
		}
		if err := c.revokeLocked(e.Addr, e.MAC, view); err != nil {
			return err
		}
		c.eventLocked("stray-grant-removed", fmt.Sprintf("granted_v4 %s %s timeout %ds", e.Addr, e.MAC, int(e.Timeout/time.Second)))
	}
	for _, e := range ks.GrantedDst {
		if _, ok := view.dst[e.Addr]; !ok {
			continue
		}
		if g := c.grantForAddrLocked(e.Addr); g != nil && c.timeoutOK(e, g, now) {
			continue
		}
		cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		err := c.kernel.RevokeDst(cctx, e.Addr)
		cancel()
		if err != nil {
			c.degradeLocked("removing stray granted_dst element failed: " + err.Error())
			return fmt.Errorf("%w: %v", ErrDegraded, err)
		}
		delete(view.dst, e.Addr)
		c.flushFlowsLocked(e.Addr)
		c.eventLocked("stray-grant-removed", fmt.Sprintf("granted_dst_v4 %s timeout %ds", e.Addr, int(e.Timeout/time.Second)))
	}
	for _, g := range c.sortedGrantsLocked() {
		gr, ok1 := view.granted[pair{g.addr, g.mac}]
		ds, ok2 := view.dst[g.addr]
		if ok1 && ok2 && min(gr.Expires, ds.Expires) >= time.Second {
			continue
		}
		reason := "lost"
		if (ok1 && ok2) || g.expires.Sub(now) <= kernelSlack {
			reason = "expired"
		}
		if err := c.endGrantLocked(g, reason, view); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) timeoutOK(e model.Element, g *grant, now time.Time) bool {
	return e.Timeout > 0 && e.Timeout <= c.cfg.GrantMax+kernelSlack && e.Timeout <= g.ttl+kernelSlack &&
		e.Expires >= 0 && e.Expires <= e.Timeout && e.Expires <= g.expires.Sub(now)+kernelSlack
}

func (c *Controller) liveLocked(g *grant, now time.Time) bool {
	l, ok := c.store.Lookup(g.leaseID)
	return ok && l.Client == g.mac.String() && now.Before(g.expires)
}

// endGrantLocked removes a desired grant and its kernel elements. With a
// view, the kernel is only written if the view still holds an element.
func (c *Controller) endGrantLocked(g *grant, reason string, view *kernelView) error {
	if view == nil || view.has(g.addr, g.mac) {
		if err := c.revokeLocked(g.addr, g.mac, view); err != nil {
			return err
		}
	} else {
		c.flushFlowsLocked(g.addr)
	}
	c.discardGrantLocked(g)
	c.eventLocked("grant-ended", fmt.Sprintf("address %s mac %s reason %s", g.addr, g.mac, reason))
	return nil
}

func (c *Controller) discardGrantLocked(g *grant) {
	c.store.Revoke(g.leaseID)
	if c.grants[g.mac] == g {
		delete(c.grants, g.mac)
	}
}

// revokeLocked removes both grant elements for (addr, mac) and flushes flows.
// Removal always uses a fresh bounded context so cancellation can never
// prevent a revocation; failure degrades.
func (c *Controller) revokeLocked(addr netip.Addr, mac model.MAC, view *kernelView) error {
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.kernel.Revoke(cctx, addr, mac); err != nil {
		c.degradeLocked("revoking grant failed: " + err.Error())
		return fmt.Errorf("%w: %v", ErrDegraded, err)
	}
	if view != nil {
		delete(view.granted, pair{addr, mac})
		delete(view.dst, addr)
	}
	c.flushFlowsLocked(addr)
	return nil
}

// flushFlowsLocked deletes conntrack state. Failure is recorded but does not
// degrade: the guard has no blanket established-accept, so conntrack entries
// cannot forward packets once the grant elements are gone.
func (c *Controller) flushFlowsLocked(addr netip.Addr) {
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.flows.Flush(cctx, addr); err != nil {
		c.eventLocked("flow-flush-failed", fmt.Sprintf("address %s", addr))
	}
}

func (c *Controller) unbindKernelLocked(addr netip.Addr, mac model.MAC, why string) {
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := c.kernel.Unbind(cctx, addr, mac); err != nil {
		c.eventLocked("unbind-failed", fmt.Sprintf("address %s mac %s", addr, mac))
		return
	}
	c.eventLocked("bound-removed", fmt.Sprintf("address %s mac %s (%s)", addr, mac, why))
}

func (c *Controller) grantForAddrLocked(addr netip.Addr) *grant {
	for _, g := range c.grants {
		if g.addr == addr {
			return g
		}
	}
	return nil
}

func (c *Controller) sortedGrantsLocked() []*grant {
	out := make([]*grant, 0, len(c.grants))
	for _, g := range c.grants {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b *grant) int { return a.addr.Compare(b.addr) })
	return out
}

func (c *Controller) pruneLocked() {
	now := c.now()
	for mac, until := range c.cooldown {
		if !now.Before(until) {
			delete(c.cooldown, mac)
		}
	}
	for mac, at := range c.lastGrant {
		if now.Sub(at) >= c.cfg.MinRequestInterval {
			delete(c.lastGrant, mac)
		}
	}
}

func (c *Controller) hostAddr(a netip.Addr) bool {
	p := c.cfg.GuestSubnet
	return a.Is4() && p.Contains(a) && a != c.cfg.Gateway && a != p.Addr() && a != lastAddr(p)
}

func validMAC(m model.MAC) bool {
	_, err := model.MACFromBytes(m[:])
	return err == nil
}

type kernelView struct {
	granted map[pair]model.Element
	dst     map[netip.Addr]model.Element
}

func newView(ks model.KernelState) *kernelView {
	v := &kernelView{granted: map[pair]model.Element{}, dst: map[netip.Addr]model.Element{}}
	for _, e := range ks.Granted {
		v.granted[pair{e.Addr, e.MAC}] = e
	}
	for _, e := range ks.GrantedDst {
		v.dst[e.Addr] = e
	}
	return v
}

func (v *kernelView) has(addr netip.Addr, mac model.MAC) bool {
	_, a := v.granted[pair{addr, mac}]
	_, b := v.dst[addr]
	return a || b
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func sortedAddrs(m map[netip.Addr]bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// eventLocked appends to the bounded audit ring. Details never carry lease IDs.
func (c *Controller) eventLocked(kind, detail string) {
	ev := ipc.EventView{At: c.now(), Kind: kind, Detail: sanitize(detail, 256)}
	if len(c.events) < c.cfg.MaxEvents {
		c.events = append(c.events, ev)
	} else {
		c.events[c.evNext] = ev
	}
	c.evNext = (c.evNext + 1) % c.cfg.MaxEvents
	c.log.Info("portcullis event", "kind", kind, "detail", ev.Detail)
}

func (c *Controller) eventsNewestFirstLocked() []ipc.EventView {
	n := len(c.events)
	out := make([]ipc.EventView, 0, n)
	for i := range n {
		out = append(out, c.events[((c.evNext-1-i)%n+n)%n])
	}
	return out
}

// sanitize keeps printable ASCII only and bounds the length.
func sanitize(s string, limit int) string {
	b := make([]byte, 0, min(len(s), limit))
	for i := 0; i < len(s) && len(b) < limit; i++ {
		if s[i] >= 0x20 && s[i] < 0x7f {
			b = append(b, s[i])
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}
