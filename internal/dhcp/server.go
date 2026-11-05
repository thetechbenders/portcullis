// Package dhcp is the built-in DHCPv4 server for the directly attached guest
// segment. Its binding table is the controller's own record of which
// Ethernet address holds which IPv4 address; it is never reported by a client
// or the portal. A binding is acknowledged only after the Sink has installed
// kernel evidence for it, and an address is reassigned only after the Sink
// has been told to remove every authority derived from its previous holder.
//
// chaddr is a claim in the payload, not an observed L2 source. A station
// that lies about chaddr obtains a binding for a MAC it does not use, which
// the kernel's ip saddr . ether saddr match makes useless. Forged RELEASE,
// DECLINE or REQUEST messages naming another station's chaddr can end that
// station's binding (denial of service) but can never create authority.
package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	// ErrBind is returned by Handle when the Sink refused a binding; no
	// ACK is produced and no binding is recorded.
	ErrBind = errors.New("kernel binding failed; request not acknowledged")
	// ErrAdopt wraps every Adopt refusal.
	ErrAdopt = errors.New("binding cannot be adopted")
)

// adoptSlack tolerates rounding of kernel-reported remaining seconds.
const adoptSlack = 2 * time.Second

// Sink receives binding lifecycle changes. It is the controller.
type Sink interface {
	// Bind must install kernel evidence for b (b.Expires is the lease end)
	// and return nil before the server sends an ACK.
	Bind(ctx context.Context, b model.Binding) error
	// Unbind removes all authority derived from b: on RELEASE, DECLINE,
	// expiry, NAK of a stale binding, or reassignment.
	Unbind(ctx context.Context, b model.Binding, reason string)
}

type offer struct {
	addr    netip.Addr
	expires time.Time
}

// Server is the DHCP protocol state machine.
//
// Locking: opMu serializes Handle and Sweep, and is held across Sink calls,
// so allocation decisions and the Bind/Unbind that make them effective are
// one atomic step with respect to other protocol messages. mu guards the
// tables and is never held across a Sink call. Lookup, LookupMAC, Bindings
// and Adopt take only mu, so a Sink (or a caller holding its own lock while
// calling them) cannot deadlock against an in-flight Handle. Addresses and
// MACs involved in an in-flight Sink call are marked busy so a concurrent
// Adopt cannot claim them.
type Server struct {
	cfg         Config
	sink        Sink
	now         func() time.Time
	log         *slog.Logger
	first, last uint32

	opMu sync.Mutex

	mu         sync.Mutex
	byAddr     map[netip.Addr]model.Binding
	byMAC      map[model.MAC]netip.Addr
	offers     map[model.MAC]offer
	offered    map[netip.Addr]model.MAC
	quarantine map[netip.Addr]time.Time
	busy       []model.Binding
	reserved   int // new bindings in flight, counted against MaxBindings

	sweepInterval time.Duration
}

// NewServer validates cfg. now must be monotonic-capable (time.Now) and must
// not call back into the server.
func NewServer(cfg Config, sink Sink, now func() time.Time, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, invalid("a binding sink is required")
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg: cfg, sink: sink, now: now, log: log,
		first: u32(cfg.PoolStart), last: u32(cfg.PoolEnd),
		byAddr:        make(map[netip.Addr]model.Binding),
		byMAC:         make(map[model.MAC]netip.Addr),
		offers:        make(map[model.MAC]offer),
		offered:       make(map[netip.Addr]model.MAC),
		quarantine:    make(map[netip.Addr]time.Time),
		sweepInterval: 2 * time.Second,
	}, nil
}

func (s *Server) inPool(a netip.Addr) bool {
	return a.Is4() && u32(a) >= s.first && u32(a) <= s.last
}

// Handle runs one client message through the RFC 2131 state machine. A nil
// reply means nothing is sent. An error with ErrBind means kernel evidence
// could not be installed and no ACK exists.
func (s *Server) Handle(ctx context.Context, req *Packet) (*Packet, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	defer s.clearBusy()
	now := s.now()
	s.expire(ctx, now)

	switch req.MsgType {
	case MsgDiscover:
		return s.discover(req, now), nil
	case MsgRequest:
		return s.request(ctx, req, now)
	case MsgRelease:
		s.release(ctx, req)
	case MsgDecline:
		s.decline(ctx, req, now)
	}
	return nil, nil // INFORM and the no-reply paths
}

// Sweep ends expired bindings (Unbind "lease-expired"), stale offers and
// finished quarantines, returning the number of bindings ended.
func (s *Server) Sweep(ctx context.Context) int {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	defer s.clearBusy()
	return s.expire(ctx, s.now())
}

// expire requires opMu. Removal from the table happens before Unbind and
// both happen before opMu is released, so no allocation can see the address
// free until Unbind has been called.
func (s *Server) expire(ctx context.Context, now time.Time) int {
	s.mu.Lock()
	var ended []model.Binding
	for _, b := range s.byAddr {
		if !now.Before(b.Expires) {
			ended = append(ended, b)
			s.removeLocked(b)
		}
	}
	for mac, o := range s.offers {
		if !now.Before(o.expires) {
			s.dropOfferLocked(mac)
		}
	}
	for addr, until := range s.quarantine {
		if !now.Before(until) {
			delete(s.quarantine, addr)
		}
	}
	s.mu.Unlock()
	slices.SortFunc(ended, func(a, b model.Binding) int { return a.Addr.Compare(b.Addr) })
	for _, b := range ended {
		s.unbind(ctx, b, "lease-expired")
	}
	// Unbind has returned for every ended binding, so their addresses may
	// now be reallocated.
	s.clearBusy()
	return len(ended)
}

// removeLocked deletes b and marks it busy until the caller's Unbind is done.
func (s *Server) removeLocked(b model.Binding) {
	delete(s.byAddr, b.Addr)
	delete(s.byMAC, b.MAC)
	s.busy = append(s.busy, b)
}

func (s *Server) dropOfferLocked(mac model.MAC) {
	if o, ok := s.offers[mac]; ok {
		delete(s.offers, mac)
		if s.offered[o.addr] == mac {
			delete(s.offered, o.addr)
		}
	}
}

func (s *Server) clearBusy() {
	s.mu.Lock()
	s.busy, s.reserved = nil, 0
	s.mu.Unlock()
}

func (s *Server) busyAddrLocked(addr netip.Addr) bool {
	for _, b := range s.busy {
		if b.Addr == addr {
			return true
		}
	}
	return false
}

func (s *Server) busyLocked(addr netip.Addr, mac model.MAC) bool {
	for _, b := range s.busy {
		if b.Addr == addr || b.MAC == mac {
			return true
		}
	}
	return false
}

// unbind never lets cancellation skip the removal of authority; the Sink's
// own command deadlines bound it.
func (s *Server) unbind(ctx context.Context, b model.Binding, reason string) {
	s.sink.Unbind(context.WithoutCancel(ctx), b, reason)
	s.log.Info("dhcp binding ended", "addr", b.Addr.String(), "mac", b.MAC.String(), "reason", reason)
}

func (s *Server) discover(req *Packet, now time.Time) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac := req.CHAddr
	if addr, ok := s.byMAC[mac]; ok {
		return s.reply(req, MsgOffer, addr)
	}
	if o, ok := s.offers[mac]; ok {
		o.expires = now.Add(s.cfg.OfferTimeout)
		s.offers[mac] = o
		return s.reply(req, MsgOffer, o.addr)
	}
	if len(s.byAddr) >= s.cfg.MaxBindings || len(s.offers) >= int(s.last-s.first)+1 {
		return nil
	}
	for v := s.first; v <= s.last; v++ {
		a := fromU32(v)
		if _, bound := s.byAddr[a]; bound {
			continue
		}
		if _, taken := s.offered[a]; taken {
			continue
		}
		if _, q := s.quarantine[a]; q || s.busyAddrLocked(a) {
			continue
		}
		s.offers[mac] = offer{addr: a, expires: now.Add(s.cfg.OfferTimeout)}
		s.offered[a] = mac
		return s.reply(req, MsgOffer, a)
	}
	s.log.Warn("dhcp pool exhausted")
	return nil
}

func (s *Server) request(ctx context.Context, req *Packet, now time.Time) (*Packet, error) {
	mac := req.CHAddr
	s.mu.Lock()
	bound, hasBinding := s.byMAC[mac]
	o, hasOffer := s.offers[mac]
	s.mu.Unlock()

	if req.ServerID.IsValid() && req.ServerID != s.cfg.ServerIP {
		// The client selected another server's offer.
		s.mu.Lock()
		s.dropOfferLocked(mac)
		s.mu.Unlock()
		return nil, nil
	}
	switch {
	case req.ServerID.IsValid() && unset4(req.CIAddr):
		// SELECTING: the requested address must be ours to give this MAC.
		want := req.RequestedIP
		if want.IsValid() && ((hasBinding && bound == want) || (hasOffer && o.addr == want)) {
			return s.bindAndAck(ctx, req, want, now)
		}
		return s.nak(ctx, req), nil
	case set4(req.CIAddr):
		// RENEWING / REBINDING.
		if (!req.RequestedIP.IsValid() || req.RequestedIP == req.CIAddr) && hasBinding && bound == req.CIAddr {
			return s.bindAndAck(ctx, req, req.CIAddr, now)
		}
		return s.nak(ctx, req), nil
	case req.RequestedIP.IsValid():
		// INIT-REBOOT: we are authoritative for this segment.
		if s.cfg.Subnet.Contains(req.RequestedIP) && hasBinding && bound == req.RequestedIP {
			return s.bindAndAck(ctx, req, req.RequestedIP, now)
		}
		return s.nak(ctx, req), nil
	}
	return nil, nil
}

// nak ends any binding the MAC holds: the client does not believe it holds
// that address, so the binding is stale authority.
func (s *Server) nak(ctx context.Context, req *Packet) *Packet {
	s.mu.Lock()
	s.dropOfferLocked(req.CHAddr)
	addr, ok := s.byMAC[req.CHAddr]
	var stale model.Binding
	if ok {
		stale = s.byAddr[addr]
		s.removeLocked(stale)
	}
	s.mu.Unlock()
	if ok {
		s.unbind(ctx, stale, "dhcp-nak")
	}
	return s.reply(req, MsgNak, netip.Addr{})
}

func (s *Server) bindAndAck(ctx context.Context, req *Packet, addr netip.Addr, now time.Time) (*Packet, error) {
	mac := req.CHAddr
	b := model.Binding{MAC: mac, Addr: addr, Expires: now.Add(s.cfg.LeaseTime)}

	s.mu.Lock()
	if owner, ok := s.byAddr[addr]; (ok && owner.MAC != mac) || !s.inPool(addr) || s.busyLocked(addr, mac) {
		s.mu.Unlock()
		return s.nak(ctx, req), nil
	}
	old, hadOld := s.byMAC[mac]
	refresh := hadOld && old == addr
	var moved model.Binding
	if hadOld && !refresh {
		moved = s.byAddr[old]
		s.removeLocked(moved)
	}
	if !refresh {
		if len(s.byAddr)+s.reserved >= s.cfg.MaxBindings {
			s.mu.Unlock()
			if hadOld {
				s.unbind(ctx, moved, "reassigned")
			}
			return s.nak(ctx, req), nil
		}
		s.reserved++
	}
	s.busy = append(s.busy, b)
	s.mu.Unlock()

	if hadOld && !refresh {
		s.unbind(ctx, moved, "reassigned")
	}
	if err := s.sink.Bind(ctx, b); err != nil {
		if !refresh {
			// Remove any partially applied evidence; the existing binding of
			// a refresh keeps its previous expiry and evidence.
			s.unbind(ctx, b, "bind-failed")
		}
		s.log.Warn("dhcp binding refused by controller; not acknowledging",
			"addr", addr.String(), "mac", mac.String(), "err", err)
		return nil, fmt.Errorf("%w: %w", ErrBind, err)
	}

	s.mu.Lock()
	s.byAddr[addr] = b
	s.byMAC[mac] = addr
	s.dropOfferLocked(mac)
	s.mu.Unlock()
	s.log.Info("dhcp ack", "addr", addr.String(), "mac", mac.String())
	return s.reply(req, MsgAck, addr), nil
}

func (s *Server) release(ctx context.Context, req *Packet) {
	if req.ServerID.IsValid() && req.ServerID != s.cfg.ServerIP {
		return
	}
	s.mu.Lock()
	s.dropOfferLocked(req.CHAddr)
	addr, ok := s.byMAC[req.CHAddr]
	ok = ok && set4(req.CIAddr) && addr == req.CIAddr
	var b model.Binding
	if ok {
		b = s.byAddr[addr]
		s.removeLocked(b)
	}
	s.mu.Unlock()
	if ok {
		s.unbind(ctx, b, "dhcp-release")
	}
}

func (s *Server) decline(ctx context.Context, req *Packet, now time.Time) {
	if (req.ServerID.IsValid() && req.ServerID != s.cfg.ServerIP) || !set4(req.RequestedIP) {
		return
	}
	want := req.RequestedIP
	s.mu.Lock()
	addr, bound := s.byMAC[req.CHAddr]
	o, offered := s.offers[req.CHAddr]
	isBound := bound && addr == want
	if !isBound && !(offered && o.addr == want) {
		s.mu.Unlock()
		return
	}
	s.quarantine[want] = now.Add(s.cfg.DeclineQuarantine)
	s.dropOfferLocked(req.CHAddr)
	var b model.Binding
	if isBound {
		b = s.byAddr[addr]
		s.removeLocked(b)
	}
	s.mu.Unlock()
	if isBound {
		s.unbind(ctx, b, "dhcp-decline")
	}
}

func (s *Server) reply(req *Packet, t MessageType, yiaddr netip.Addr) *Packet {
	zero := netip.AddrFrom4([4]byte{})
	p := &Packet{
		Op: opReply, HType: htypeEthernet, HLen: hlenEthernet,
		XID: req.XID, Flags: req.Flags, CHAddr: req.CHAddr,
		CIAddr: zero, YIAddr: zero, SIAddr: zero, GIAddr: zero,
		MsgType: t, ServerID: s.cfg.ServerIP,
	}
	if t == MsgNak {
		return p
	}
	p.YIAddr = yiaddr
	if t == MsgAck && set4(req.CIAddr) {
		p.CIAddr = req.CIAddr
	}
	lease := s.cfg.LeaseTime
	p.LeaseTime = lease
	p.Renewal = (lease / 2).Truncate(time.Second)
	p.Rebind = (lease * 7 / 8).Truncate(time.Second)
	p.SubnetBits = s.cfg.Subnet.Bits()
	p.Router, p.DNS = s.cfg.Router, s.cfg.DNS
	return p
}

// Lookup returns the live binding for addr.
func (s *Server) Lookup(addr netip.Addr) (model.Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.byAddr[addr]
	if !ok || !s.now().Before(b.Expires) {
		return model.Binding{}, false
	}
	return b, true
}

// LookupMAC returns the live binding held by mac.
func (s *Server) LookupMAC(mac model.MAC) (model.Binding, bool) {
	s.mu.Lock()
	addr, ok := s.byMAC[mac]
	s.mu.Unlock()
	if !ok {
		return model.Binding{}, false
	}
	return s.Lookup(addr)
}

// Bindings returns every live binding sorted by address.
func (s *Server) Bindings() []model.Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]model.Binding, 0, len(s.byAddr))
	for _, b := range s.byAddr {
		if now.Before(b.Expires) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b model.Binding) int { return a.Addr.Compare(b.Addr) })
	return out
}

// Adopt restores a binding recovered from a kernel bound_v4 element after a
// restart. It never calls the Sink. Anything not exactly consistent with
// the pool and the existing table is refused so the caller deletes it.
func (s *Server) Adopt(b model.Binding) error {
	if _, err := model.MACFromBytes(b.MAC[:]); err != nil {
		return fmt.Errorf("%w: invalid MAC", ErrAdopt)
	}
	if !s.inPool(b.Addr) {
		return fmt.Errorf("%w: %s is outside the pool", ErrAdopt, b.Addr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	switch {
	case !now.Before(b.Expires):
		return fmt.Errorf("%w: expired", ErrAdopt)
	case b.Expires.After(now.Add(s.cfg.LeaseTime + adoptSlack)):
		return fmt.Errorf("%w: lifetime exceeds the lease time", ErrAdopt)
	}
	if _, dup := s.byAddr[b.Addr]; dup {
		return fmt.Errorf("%w: duplicate address %s", ErrAdopt, b.Addr)
	}
	if _, dup := s.byMAC[b.MAC]; dup {
		return fmt.Errorf("%w: duplicate MAC", ErrAdopt)
	}
	if until, q := s.quarantine[b.Addr]; (q && now.Before(until)) || s.busyLocked(b.Addr, b.MAC) {
		return fmt.Errorf("%w: address in use", ErrAdopt)
	}
	if len(s.byAddr)+s.reserved >= s.cfg.MaxBindings {
		return fmt.Errorf("%w: binding table full", ErrAdopt)
	}
	// Kernel evidence wins over a soft offer reservation.
	if owner, ok := s.offered[b.Addr]; ok {
		s.dropOfferLocked(owner)
	}
	s.dropOfferLocked(b.MAC)
	s.byAddr[b.Addr] = b
	s.byMAC[b.MAC] = b.Addr
	return nil
}
