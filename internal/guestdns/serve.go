package guestdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrListenAddr rejects listener addresses other than one specific unicast
// IPv4 address with a nonzero port.
var ErrListenAddr = errors.New("guest DNS must listen on a specific unicast IPv4 address and nonzero port")

// ErrServe wraps socket failures that stop Serve before its context ends.
var ErrServe = errors.New("guest DNS responder stopped")

const writeTimeout = time.Second

// aLongTimeAgo is a deadline in the past, used to unblock a pending read.
var aLongTimeAgo = time.Unix(1, 0)

// limits configures the per-Serve rate limiters. Rates are tokens per
// second; a bucket starts full at its burst size.
type limits struct {
	globalRate, globalBurst float64
	sourceRate, sourceBurst float64
	maxSources              int
}

// defaultLimits allow an ordinary device's join-time burst of probe and
// background lookups while bounding the whole responder to a few hundred
// small replies per second.
var defaultLimits = limits{
	globalRate: 200, globalBurst: 400,
	sourceRate: 20, sourceBurst: 40,
	maxSources: 4096,
}

// ListenUDP opens the guest DNS socket on exactly addr. A wildcard address
// is refused: the responder must be reachable only on the gateway's guest
// address, where the kernel guard admits bound guests (ip saddr . ether
// saddr @bound_v4) and nobody else from the guest interface.
func ListenUDP(addr netip.AddrPort) (net.PacketConn, error) {
	a := addr.Addr()
	if !addr.IsValid() || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == limitedBroadcast || addr.Port() == 0 {
		return nil, fmt.Errorf("%w: %s", ErrListenAddr, addr)
	}
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, fmt.Errorf("guest DNS listen %s: %w", addr, err)
	}
	return conn, nil
}

// Serve answers queries on conn from a single goroutine until ctx is
// cancelled, then returns nil. A socket error before cancellation is
// returned wrapped in ErrServe. Serve never closes conn; on cancellation it
// unblocks the pending read by moving the read deadline into the past.
//
// Each datagram is checked in this order: size (anything over
// MaxQueryBytes is detected with a one-byte-larger buffer and dropped, not
// truncated), a usable IPv4 source with a nonzero port, the per-source
// token bucket, the global token bucket, and finally Respond. The
// per-source check comes first so one noisy guest exhausts only its own
// budget. Queries over budget are dropped without a reply. Nothing about a
// query is ever logged.
func (r *Responder) Serve(ctx context.Context, conn net.PacketConn) error {
	if conn == nil {
		return fmt.Errorf("%w: nil connection", ErrServe)
	}
	if ctx.Err() != nil {
		return nil
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(aLongTimeAgo) })
	defer stop()

	global := newBucket(r.limits.globalBurst, r.now())
	sources := newSourceLimiter(r.limits)
	buf := make([]byte, MaxQueryBytes+1)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			// The only deadline Serve sets on reads is the cancellation
			// one, so any read error before cancellation is fatal rather
			// than retried in a loop.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%w: read: %w", ErrServe, err)
		}
		r.stats.received.Add(1)
		src, ok := sourceOf(from)
		if !ok || n > MaxQueryBytes {
			r.stats.dropped.Add(1)
			continue
		}
		now := r.now()
		if !sources.allow(src.Addr(), now) || !global.allow(now, r.limits.globalRate, r.limits.globalBurst) {
			r.stats.limited.Add(1)
			continue
		}
		resp, ok := r.Respond(buf[:n])
		if !ok {
			r.stats.dropped.Add(1)
			continue
		}
		// A bounded write keeps a congested socket from stalling the loop
		// (and with it cancellation) indefinitely.
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.WriteTo(resp, from); err != nil {
			r.stats.writeErrors.Add(1)
			continue
		}
		r.stats.answered.Add(1)
	}
}

// sourceOf accepts only an IPv4 UDP source that can be replied to.
func sourceOf(from net.Addr) (netip.AddrPort, bool) {
	u, ok := from.(*net.UDPAddr)
	if !ok || u == nil {
		return netip.AddrPort{}, false
	}
	ap := u.AddrPort()
	a := ap.Addr().Unmap()
	if !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == limitedBroadcast || ap.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, ap.Port()), true
}

// bucket is a token bucket driven by an injected clock. A clock that moves
// backwards never adds tokens.
type bucket struct {
	tokens float64
	last   time.Time
}

func newBucket(burst float64, now time.Time) bucket { return bucket{tokens: burst, last: now} }

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(burst, b.tokens+elapsed.Seconds()*rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sourceLimiter keeps one bucket per source address in a bounded map.
// Only the Serve goroutine touches it, so it needs no lock.
type sourceLimiter struct {
	rate, burst float64
	max         int
	idle        time.Duration
	buckets     map[netip.Addr]*bucket
	lastSweep   time.Time
	swept       bool
}

func newSourceLimiter(l limits) *sourceLimiter {
	idle := time.Second
	if l.sourceRate > 0 {
		idle = time.Duration(l.sourceBurst / l.sourceRate * float64(time.Second))
	}
	return &sourceLimiter{
		rate: l.sourceRate, burst: l.sourceBurst, max: l.maxSources, idle: idle,
		buckets: make(map[netip.Addr]*bucket),
	}
}

// allow charges one query to src. When the map is full it evicts buckets
// that have been idle long enough to have refilled completely (dropping
// such a bucket is indistinguishable from keeping it, so eviction never
// raises any source's budget). If every tracked source is still active the
// new source is refused rather than evicting a live bucket: that would hand
// a flooding source a fresh burst. The kernel guard already confines
// sources to bound guests, far fewer than maxSources.
func (l *sourceLimiter) allow(src netip.Addr, now time.Time) bool {
	if b, ok := l.buckets[src]; ok {
		return b.allow(now, l.rate, l.burst)
	}
	if len(l.buckets) >= l.max {
		l.sweep(now)
		if len(l.buckets) >= l.max {
			return false
		}
	}
	b := newBucket(l.burst, now)
	l.buckets[src] = &b
	return b.allow(now, l.rate, l.burst)
}

// sweep runs at most once per second so a full map of active sources
// cannot turn every new datagram into a full scan.
func (l *sourceLimiter) sweep(now time.Time) {
	if l.swept && now.Sub(l.lastSweep) < time.Second {
		return
	}
	l.swept, l.lastSweep = true, now
	for addr, b := range l.buckets {
		if now.Sub(b.last) >= l.idle {
			delete(l.buckets, addr)
		}
	}
}
