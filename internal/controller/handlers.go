package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/model"
)

const (
	reasonUnavailable  = "Enforcement could not be verified. Access remains blocked."
	reasonUnrecognized = "This device isn't recognized on the guest network yet. Reconnect so it receives an address."
	reasonAmbiguous    = "Your connection couldn't be verified against the gateway's network evidence"
	reasonDenied       = "This device has no active access."
	reasonGranted      = "Access verified by the gateway firewall."
	reasonRevoked      = "Access for this device was revoked by the operator."
	reasonLeaseEnding  = "Your address lease is about to end. Reconnect to renew it."
)

var redact = regexp.MustCompile(`[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}|\d{1,3}(\.\d{1,3}){3}`)

// GuestHandler serves status/request/release on the guest socket. The guest
// is identified ONLY from the kernel-observed peer address of the passed
// connection and the controller's own DHCP binding for it.
func (c *Controller) GuestHandler() ipc.Handler { return ipc.HandlerFunc(c.handleGuest) }

// OperatorHandler serves snapshot/revoke/reset on the operator socket.
func (c *Controller) OperatorHandler() ipc.Handler { return ipc.HandlerFunc(c.handleOperator) }

func failure(code ipc.ErrorCode, msg string, s *ipc.Session) ipc.Response {
	return ipc.Response{OK: false, Error: code, Message: msg, Session: s}
}

func success(s ipc.Session) ipc.Response { return ipc.Response{OK: true, Session: &s} }

func (c *Controller) baseSession() ipc.Session {
	return ipc.Session{
		DefaultDurationSeconds: int(c.cfg.GrantDefault / time.Second),
		MaxDurationSeconds:     int(c.cfg.GrantMax / time.Second),
	}
}

func (c *Controller) unavailable() ipc.Response {
	s := c.baseSession()
	s.State, s.Reason = ipc.StateUnavailable, reasonUnavailable
	return failure(ipc.ErrUnavailable, "enforcement unavailable", &s)
}

// identityResult answers an unverified guest: status describes the state,
// mutating operations fail with ErrIdentity.
func identityResult(op ipc.Op, s ipc.Session) ipc.Response {
	if op == ipc.OpStatus {
		return success(s)
	}
	return failure(ipc.ErrIdentity, "the connection could not be attributed to a verified binding", &s)
}

func (c *Controller) handleGuest(ctx context.Context, _ ipc.Peer, req ipc.Request, guest *ipc.GuestConn) ipc.Response {
	if guest == nil {
		return failure(ipc.ErrForbidden, "guest operations require the guest connection", nil)
	}
	switch req.Op {
	case ipc.OpStatus, ipc.OpRelease:
		if req.DurationSeconds != 0 || req.Target != "" {
			return failure(ipc.ErrBadRequest, "unexpected request fields", nil)
		}
	case ipc.OpRequest:
		if req.Target != "" {
			return failure(ipc.ErrBadRequest, "unexpected request fields", nil)
		}
	default:
		return failure(ipc.ErrForbidden, "operation not allowed on the guest socket", nil)
	}

	addr := guest.Remote.Addr()
	if !c.hostAddr(addr) || guest.Remote.Port() == 0 || guest.Local.Addr() != c.cfg.Gateway {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.readyLocked() != nil {
			return c.unavailable()
		}
		s := c.baseSession()
		s.State, s.Reason = ipc.StateUnrecognized, reasonUnrecognized
		return identityResult(req.Op, s)
	}

	var b model.Binding
	var found bool
	consistent, err := c.lockAfterRead(func(bs Bindings) { b, found = bs.Lookup(addr) })
	defer c.mu.Unlock()
	if err != nil {
		return c.unavailable()
	}
	if !consistent {
		return failure(ipc.ErrConflict, "the address binding changed during the request; retry", nil)
	}
	s := c.baseSession()
	s.ClientAddress = addr.String()
	now := c.now()
	if !found || b.Addr != addr || !validMAC(b.MAC) || !now.Before(b.Expires) {
		s.State, s.Reason = ipc.StateUnrecognized, reasonUnrecognized
		return identityResult(req.Op, s)
	}
	s.ClientMACHint = b.MAC.Hint()

	if err := c.evidence.Corroborate(addr, b); err != nil {
		c.log.Warn("neighbour evidence conflict", "address", addr.String(), "err", err)
		c.eventLocked("evidence-conflict", fmt.Sprintf("address %s mac %s (%s)", addr, b.MAC, errorClass(err)))
		// Conflicting evidence ends any grant for this binding: replies
		// would otherwise follow a possibly poisoned neighbour entry.
		for _, g := range c.sortedGrantsLocked() {
			if g.mac == b.MAC || g.addr == addr {
				_ = c.endGrantLocked(g, "ambiguous-evidence", nil)
			}
		}
		if c.degraded {
			return c.unavailable()
		}
		s.State = ipc.StateAmbiguous
		s.Reason = reasonAmbiguous + " (" + errorClass(err) + ")."
		return identityResult(req.Op, s)
	}

	// Desired grants must belong to exactly this binding; an operator
	// cooldown excludes any grant.
	_, cooling := c.cooldown[b.MAC]
	for _, g := range c.sortedGrantsLocked() {
		if (g.mac == b.MAC) != (g.addr == addr) || (g.mac == b.MAC && cooling && now.Before(c.cooldown[b.MAC])) {
			if err := c.endGrantLocked(g, "binding-changed", nil); err != nil {
				return c.unavailable()
			}
		}
	}
	if c.degraded {
		return c.unavailable()
	}
	ks, err := c.readKernelLocked(ctx, false, false)
	if err != nil {
		return c.unavailable()
	}
	switch req.Op {
	case ipc.OpStatus:
		return success(c.sessionLocked(b, ks, s))
	case ipc.OpRelease:
		if g := c.grants[b.MAC]; g != nil {
			if err := c.endGrantLocked(g, "released", nil); err != nil {
				return c.unavailable()
			}
		}
		return success(c.sessionLocked(b, ks, s))
	default:
		return c.requestLocked(ctx, b, ks, s, req.DurationSeconds)
	}
}

// sessionLocked derives the guest state. Granted is reported ONLY when a
// desired grant for this exact binding survived enforcement against ks and
// both kernel elements are timed and present; remaining time comes from the
// kernel.
func (c *Controller) sessionLocked(b model.Binding, ks model.KernelState, s ipc.Session) ipc.Session {
	now := c.now()
	if until, ok := c.cooldown[b.MAC]; ok && now.Before(until) {
		s.State, s.Reason = ipc.StateRevoked, reasonRevoked
		s.RetryAfterSeconds = ceilSeconds(until.Sub(now))
		return s
	}
	if g := c.grants[b.MAC]; g != nil && g.addr == b.Addr {
		if rem, ok := kernelRemaining(ks, g); ok {
			s.State, s.Reason = ipc.StateGranted, reasonGranted
			s.RemainingSeconds = int(rem / time.Second)
			s.GrantedSeconds = int(g.ttl / time.Second)
			return s
		}
	}
	s.State, s.Reason = ipc.StateDenied, reasonDenied
	if last, ok := c.lastGrant[b.MAC]; ok && now.Sub(last) < c.cfg.MinRequestInterval {
		s.RetryAfterSeconds = ceilSeconds(c.cfg.MinRequestInterval - now.Sub(last))
		return s
	}
	if b.Expires.Sub(now) < minGrant {
		s.Reason = reasonLeaseEnding
		return s
	}
	s.CanRequest = true
	return s
}

func kernelRemaining(ks model.KernelState, g *grant) (time.Duration, bool) {
	var gr, ds *model.Element
	for i := range ks.Granted {
		if e := &ks.Granted[i]; e.Addr == g.addr && e.MAC == g.mac && e.Timeout > 0 {
			gr = e
		}
	}
	for i := range ks.GrantedDst {
		if e := &ks.GrantedDst[i]; e.Addr == g.addr && e.Timeout > 0 {
			ds = e
		}
	}
	if gr == nil || ds == nil {
		return 0, false
	}
	rem := min(gr.Expires, ds.Expires)
	return rem, rem >= time.Second
}

func (c *Controller) requestLocked(ctx context.Context, b model.Binding, ks model.KernelState, s ipc.Session, seconds int) ipc.Response {
	d := c.cfg.GrantDefault
	if seconds != 0 {
		if seconds < int(minGrant/time.Second) || seconds > int(c.cfg.GrantMax/time.Second) {
			cur := c.sessionLocked(b, ks, s)
			return failure(ipc.ErrBadRequest, "requested duration is outside the allowed range", &cur)
		}
		d = time.Duration(seconds) * time.Second
	}
	cur := c.sessionLocked(b, ks, s)
	switch cur.State {
	case ipc.StateGranted:
		return success(cur) // idempotent: no second kernel write
	case ipc.StateRevoked:
		return failure(ipc.ErrForbidden, "access was revoked by the operator; retry later", &cur)
	}
	now := c.now()
	if last, ok := c.lastGrant[b.MAC]; ok && now.Sub(last) < c.cfg.MinRequestInterval {
		return failure(ipc.ErrRateLimited, "requests are rate limited", &cur)
	}
	ttl := min(d, b.Expires.Sub(now)).Truncate(time.Second)
	if ttl < minGrant {
		return failure(ipc.ErrConflict, "your address lease is about to end; renew your connection", &cur)
	}
	if ctx.Err() != nil {
		return c.unavailable()
	}
	if g := c.grantForAddrLocked(b.Addr); g != nil {
		if err := c.endGrantLocked(g, "binding-changed", nil); err != nil {
			return c.unavailable()
		}
	}
	l, err := c.store.Issue(b.MAC.String(), ttl)
	if err != nil {
		return failure(ipc.ErrUnavailable, "the grant could not be recorded", &cur)
	}
	g := &grant{leaseID: l.ID, addr: b.Addr, mac: b.MAC, ttl: ttl, expires: l.ExpiresAt}
	c.grants[b.MAC] = g

	if err := c.kernel.Grant(ctx, b.Addr, b.MAC, ttl); err != nil {
		// The transaction may or may not have committed: drop the record,
		// remove whatever exists and re-attest.
		c.discardGrantLocked(g)
		c.log.Warn("kernel grant failed", "err", err)
		c.eventLocked("grant-failed", fmt.Sprintf("address %s mac %s", b.Addr, b.MAC))
		if c.revokeLocked(b.Addr, b.MAC, nil) == nil {
			cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
			_, _ = c.readKernelLocked(cctx, true, true)
			cancel()
		}
		return c.unavailable()
	}

	// Never report a grant without reading it back from the attested guard.
	cctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	ks, err = c.readKernelLocked(cctx, false, true)
	cancel()
	if err != nil {
		return c.unavailable()
	}
	cur = c.sessionLocked(b, ks, s)
	if cur.State != ipc.StateGranted {
		if c.grants[b.MAC] == g {
			if err := c.endGrantLocked(g, "not-effective", nil); err != nil {
				return c.unavailable()
			}
			cur = c.sessionLocked(b, ks, s)
		}
		return failure(ipc.ErrInternal, "grant was not effective", &cur)
	}
	c.lastGrant[b.MAC] = now
	c.eventLocked("grant", fmt.Sprintf("address %s mac %s seconds %d", b.Addr, b.MAC, int(ttl/time.Second)))
	return success(cur)
}

func (c *Controller) handleOperator(ctx context.Context, _ ipc.Peer, req ipc.Request, guest *ipc.GuestConn) ipc.Response {
	if guest != nil {
		return failure(ipc.ErrForbidden, "operator operations do not accept a guest connection", nil)
	}
	switch req.Op {
	case ipc.OpSnapshot:
		if req.DurationSeconds != 0 || req.Target != "" {
			return failure(ipc.ErrBadRequest, "unexpected request fields", nil)
		}
		return c.snapshot()
	case ipc.OpRevoke:
		mac, err := model.ParseMAC(req.Target)
		if err != nil || req.DurationSeconds != 0 {
			return failure(ipc.ErrBadRequest, "revoke requires a unicast MAC target", nil)
		}
		return c.operatorRevoke(ctx, mac)
	case ipc.OpReset:
		if req.DurationSeconds != 0 || req.Target != "" {
			return failure(ipc.ErrBadRequest, "unexpected request fields", nil)
		}
		return c.reset()
	default:
		return failure(ipc.ErrForbidden, "operation not allowed on the operator socket", nil)
	}
}

func (c *Controller) snapshot() ipc.Response {
	c.mu.Lock()
	if c.phase != phaseRunning {
		c.mu.Unlock()
		return failure(ipc.ErrUnavailable, "controller is not running", nil)
	}
	bs := c.bindings
	c.mu.Unlock()
	list := bs.Bindings() // outside mu: lock order is DHCP → controller

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	age := now.Sub(c.lastRead)
	snap := &ipc.Snapshot{
		GeneratedAt: now, Enforcement: "ok", Isolation: "not_required", LastAttestation: c.lastAttest,
		Bindings: []ipc.BindingView{}, Grants: []ipc.GrantView{},
		Counters: []ipc.CounterView{}, Events: c.eventsNewestFirstLocked(),
	}
	if c.degraded {
		snap.Enforcement, snap.DegradedReason = "degraded", c.reason
		snap.Isolation = "unconfirmed"
		if c.isolated {
			snap.Isolation = "confirmed"
		}
	}
	for _, b := range list {
		v := ipc.BindingView{Address: b.Addr.String(), MAC: b.MAC.String(),
			LeaseRemainingSeconds: max(int(b.Expires.Sub(now)/time.Second), 0), State: ipc.StateDenied}
		switch until, cooling := c.cooldown[b.MAC]; {
		case c.degraded:
			v.State = ipc.StateUnavailable
		case cooling && now.Before(until):
			v.State, v.RevokedForSeconds = ipc.StateRevoked, ceilSeconds(until.Sub(now))
		default:
			if g := c.grants[b.MAC]; g != nil && g.addr == b.Addr {
				if _, ok := kernelRemaining(c.last, g); ok {
					v.State = ipc.StateGranted
				}
			}
		}
		snap.Bindings = append(snap.Bindings, v)
	}
	for _, g := range c.sortedGrantsLocked() {
		v := ipc.GrantView{Address: g.addr.String(), MAC: g.mac.String(),
			GrantedSeconds:          int(g.ttl / time.Second),
			DesiredRemainingSeconds: max(int(g.expires.Sub(now)/time.Second), 0)}
		if rem, ok := kernelRemaining(c.last, g); ok {
			v.KernelPresent = true
			v.KernelRemainingSeconds = max(int((rem-age)/time.Second), 0)
		}
		snap.Grants = append(snap.Grants, v)
	}
	for _, ct := range c.last.Counters {
		snap.Counters = append(snap.Counters, ipc.CounterView{Rule: ct.Rule, Packets: ct.Packets, Bytes: ct.Bytes})
	}
	return ipc.Response{OK: true, Snapshot: snap}
}

// operatorRevoke ends any grant for mac and sets the cooldown, even when the
// MAC holds no grant. The cooldown is keyed by MAC so DHCP renewal or a
// reconnect does not clear it.
func (c *Controller) operatorRevoke(ctx context.Context, mac model.MAC) ipc.Response {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseRunning {
		return failure(ipc.ErrUnavailable, "controller is not running", nil)
	}
	if c.cfg.RevokeCooldown > 0 {
		c.cooldown[mac] = c.now().Add(c.cfg.RevokeCooldown)
	}
	if c.degraded {
		return failure(ipc.ErrUnavailable, "enforcement degraded; all grants were already flushed", nil)
	}
	if g := c.grants[mac]; g != nil {
		if err := c.endGrantLocked(g, "operator-revoked", nil); err != nil {
			return failure(ipc.ErrUnavailable, "revocation failed; enforcement degraded", nil)
		}
	}
	// Any kernel element for this MAC is now undesired and is removed here.
	if _, err := c.readKernelLocked(ctx, false, false); err != nil {
		return failure(ipc.ErrUnavailable, "revocation could not be confirmed", nil)
	}
	c.eventLocked("revoke", fmt.Sprintf("mac %s cooldown %ds", mac, int(c.cfg.RevokeCooldown/time.Second)))
	return ipc.Response{OK: true}
}

// reset revokes every grant and clears cooldowns and rate limits. DHCP
// bindings and bound elements are kept.
func (c *Controller) reset() ipc.Response {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase != phaseRunning {
		return failure(ipc.ErrUnavailable, "controller is not running", nil)
	}
	clear(c.cooldown)
	clear(c.lastGrant)
	if c.degraded {
		return failure(ipc.ErrUnavailable, "enforcement degraded; restart required", nil)
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
		c.degradeLocked("flushing grants on reset failed: " + err.Error())
		return failure(ipc.ErrUnavailable, "reset failed; enforcement degraded", nil)
	}
	for _, a := range sortedAddrs(addrs) {
		c.flushFlowsLocked(a)
	}
	if _, err := c.readKernelLocked(cctx, false, true); err != nil {
		return failure(ipc.ErrUnavailable, "reset could not be confirmed", nil)
	}
	c.eventLocked("reset", fmt.Sprintf("%d addresses", len(addrs)))
	return ipc.Response{OK: true}
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// errorClass returns the innermost wrapped error text (normally a sentinel),
// printable, bounded and with addresses redacted, for guest-facing reasons.
func errorClass(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			break
		}
		err = inner
	}
	return redact.ReplaceAllString(sanitize(err.Error(), 96), "*")
}
