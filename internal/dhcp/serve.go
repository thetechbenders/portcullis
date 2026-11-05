package dhcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

const (
	clientPort     = 68
	globalRate     = 100.0
	globalBurst    = 200.0
	macRate        = 10.0
	macBurst       = 10.0
	maxTrackedMACs = 4096
	writeTimeout   = time.Second
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	} else if d := now.Sub(b.last); d > 0 {
		b.tokens = min(burst, b.tokens+d.Seconds()*rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiter is owned by the single Serve goroutine.
type limiter struct {
	global bucket
	perMAC map[model.MAC]*bucket
}

func (l *limiter) allowMAC(mac model.MAC, now time.Time) bool {
	b, ok := l.perMAC[mac]
	if !ok {
		if len(l.perMAC) >= maxTrackedMACs {
			// Evict buckets that have refilled completely; they carry no state.
			for m, old := range l.perMAC {
				if now.Sub(old.last).Seconds()*macRate+old.tokens >= macBurst {
					delete(l.perMAC, m)
				}
			}
			if len(l.perMAC) >= maxTrackedMACs {
				return false
			}
		}
		b = &bucket{}
		l.perMAC[mac] = b
	}
	return b.allow(now, macRate, macBurst)
}

// Serve runs the single read loop on conn until ctx is cancelled (then it
// returns nil). Malformed and rate-limited datagrams are dropped silently;
// packet payload is never logged. Replies are broadcast to
// 255.255.255.255:68 because a client without an address cannot receive
// unicast unless the server injects an ARP entry. Sweep runs every few
// seconds from the same loop, driven by read deadlines.
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	if conn == nil {
		return errors.New("dhcp: nil packet connection")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()

	// One spare byte detects (and rejects) datagrams longer than maxPacket
	// that the kernel would otherwise truncate silently.
	buf := make([]byte, maxPacket+1)
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}
	lim := &limiter{perMAC: make(map[model.MAC]*bucket)}
	nextSweep := time.Now().Add(s.sweepInterval)
	for {
		if err := conn.SetReadDeadline(nextSweep); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dhcp: set read deadline: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		n, from, err := conn.ReadFrom(buf)
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case err == nil:
			s.serveOne(ctx, conn, lim, buf[:n], from, dst)
		case errors.Is(err, os.ErrDeadlineExceeded):
		default:
			return fmt.Errorf("dhcp: read: %w", err)
		}
		if !time.Now().Before(nextSweep) {
			s.Sweep(ctx)
			nextSweep = time.Now().Add(s.sweepInterval)
		}
	}
}

func (s *Server) serveOne(ctx context.Context, conn net.PacketConn, lim *limiter, pkt []byte, from net.Addr, dst net.Addr) {
	now := s.now()
	if !lim.global.allow(now, globalRate, globalBurst) {
		return
	}
	if ua, ok := from.(*net.UDPAddr); !ok || ua.Port != clientPort {
		s.log.Debug("dhcp datagram not from the client port")
		return
	}
	req, err := ParseRequest(pkt)
	if err != nil {
		s.log.Debug("ignoring malformed dhcp datagram", "err", err)
		return
	}
	if !lim.allowMAC(req.CHAddr, now) {
		s.log.Debug("dhcp per-client rate limit", "mac", req.CHAddr.String())
		return
	}
	reply, err := s.Handle(ctx, req)
	if err != nil || reply == nil {
		return
	}
	out, err := reply.MarshalReply()
	if err != nil {
		s.log.Error("dhcp reply could not be encoded", "err", err)
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.WriteTo(out, dst); err != nil {
		s.log.Warn("dhcp reply send failed", "err", err)
	}
}
