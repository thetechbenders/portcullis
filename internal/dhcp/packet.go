package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

var (
	// ErrMalformed wraps every request rejected by ParseRequest or Handle.
	// Error text never contains packet payload.
	ErrMalformed = errors.New("malformed DHCP request")
	// ErrReply wraps reply packets that cannot be marshalled safely.
	ErrReply = errors.New("invalid DHCP reply")
)

const (
	headerLen   = 236 // fixed BOOTP header
	minPacket   = headerLen + 4
	maxPacket   = 1500
	minReply    = 300 // BOOTP minimum message size
	maxClientID = 64

	opRequest     = 1
	opReply       = 2
	htypeEthernet = 1
	hlenEthernet  = 6
)

var magicCookie = []byte{99, 130, 83, 99}

const (
	optPad          = 0
	optSubnetMask   = 1
	optRouter       = 3
	optDNS          = 6
	optRequestedIP  = 50
	optLeaseTime    = 51
	optOverload     = 52
	optMessageType  = 53
	optServerID     = 54
	optParamRequest = 55
	optRenewal      = 58
	optRebind       = 59
	optClientID     = 61
	optEnd          = 255
)

// MessageType is DHCP option 53.
type MessageType uint8

const (
	MsgDiscover MessageType = 1
	MsgOffer    MessageType = 2
	MsgRequest  MessageType = 3
	MsgDecline  MessageType = 4
	MsgAck      MessageType = 5
	MsgNak      MessageType = 6
	MsgRelease  MessageType = 7
	MsgInform   MessageType = 8
)

func (t MessageType) String() string {
	names := [...]string{"", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"}
	if int(t) < len(names) && t != 0 {
		return names[t]
	}
	return fmt.Sprintf("MessageType(%d)", uint8(t))
}

func clientMessage(t MessageType) bool {
	switch t {
	case MsgDiscover, MsgRequest, MsgDecline, MsgRelease, MsgInform:
		return true
	}
	return false
}

// Packet is a parsed DHCPv4 request or a reply under construction. Address
// options that are absent are the zero netip.Addr.
type Packet struct {
	Op, HType, HLen, Hops uint8
	XID                   uint32
	Secs, Flags           uint16
	CIAddr, YIAddr        netip.Addr
	SIAddr, GIAddr        netip.Addr
	CHAddr                model.MAC

	MsgType      MessageType
	RequestedIP  netip.Addr
	ServerID     netip.Addr
	ClientID     []byte // at most 64 bytes; never used as identity
	ParamRequest []byte

	// Reply options.
	LeaseTime, Renewal, Rebind time.Duration
	SubnetBits                 int
	Router, DNS                netip.Addr
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

// set4 reports whether a is a non-zero IPv4 address.
func set4(a netip.Addr) bool { return a.Is4() && !a.IsUnspecified() }

// unset4 reports whether a is absent or 0.0.0.0.
func unset4(a netip.Addr) bool { return !a.IsValid() || (a.Is4() && a.IsUnspecified()) }

// ParseRequest strictly decodes one client message. Relayed requests are
// rejected: Portcullis serves only the directly attached guest segment, so
// a relay could only be an attacker trying to obtain bindings for a link the
// kernel guard does not model. Byte slices are copied; b may be reused.
func ParseRequest(b []byte) (*Packet, error) {
	if len(b) < minPacket || len(b) > maxPacket {
		return nil, malformed("length %d outside [%d, %d]", len(b), minPacket, maxPacket)
	}
	p := &Packet{
		Op: b[0], HType: b[1], HLen: b[2], Hops: b[3],
		XID:    binary.BigEndian.Uint32(b[4:8]),
		Secs:   binary.BigEndian.Uint16(b[8:10]),
		Flags:  binary.BigEndian.Uint16(b[10:12]),
		CIAddr: addr4(b[12:16]), YIAddr: addr4(b[16:20]),
		SIAddr: addr4(b[20:24]), GIAddr: addr4(b[24:28]),
	}
	mac, err := model.MACFromBytes(b[28:34])
	if err != nil {
		return nil, malformed("chaddr is not a non-zero unicast Ethernet address")
	}
	p.CHAddr = mac
	if !bytes.Equal(b[34:44], make([]byte, 10)) {
		return nil, malformed("chaddr padding is not zero")
	}
	if !bytes.Equal(b[headerLen:minPacket], magicCookie) {
		return nil, malformed("bad magic cookie")
	}
	if err := parseOptions(p, b[minPacket:]); err != nil {
		return nil, err
	}
	if err := validateRequest(p); err != nil {
		return nil, err
	}
	return p, nil
}

func parseOptions(p *Packet, opts []byte) error {
	var seen [256]bool
	i, ended := 0, false
	for i < len(opts) {
		code := opts[i]
		if code == optPad {
			i++
			continue
		}
		if code == optEnd {
			ended = true
			i++
			break
		}
		if i+1 >= len(opts) {
			return malformed("option %d truncated", code)
		}
		start := i + 2
		end := start + int(opts[i+1])
		if end > len(opts) {
			return malformed("option %d overruns packet", code)
		}
		if seen[code] {
			return malformed("duplicate option %d", code)
		}
		seen[code] = true
		val := opts[start:end]
		switch code {
		case optOverload:
			return malformed("option overload is not supported")
		case optMessageType:
			if len(val) != 1 || !clientMessage(MessageType(val[0])) {
				return malformed("invalid client message type")
			}
			p.MsgType = MessageType(val[0])
		case optRequestedIP, optServerID:
			if len(val) != 4 {
				return malformed("option %d must be 4 bytes", code)
			}
			if code == optRequestedIP {
				p.RequestedIP = addr4(val)
			} else {
				p.ServerID = addr4(val)
			}
		case optClientID:
			if len(val) < 2 || len(val) > maxClientID {
				return malformed("client identifier length %d", len(val))
			}
			p.ClientID = slices.Clone(val)
		case optParamRequest:
			if len(val) == 0 {
				return malformed("empty parameter request list")
			}
			p.ParamRequest = slices.Clone(val)
		}
		i = end
	}
	if !ended {
		return malformed("missing end option")
	}
	for _, c := range opts[i:] {
		if c != 0 {
			return malformed("data after end option")
		}
	}
	if !seen[optMessageType] {
		return malformed("missing message type")
	}
	return nil
}

// validateRequest re-checks the invariants ParseRequest guarantees so that
// Handle is safe on hand-built packets too.
func validateRequest(p *Packet) error {
	if p == nil {
		return malformed("nil packet")
	}
	if p.Op != opRequest || p.HType != htypeEthernet || p.HLen != hlenEthernet {
		return malformed("not an Ethernet BOOTREQUEST")
	}
	if p.Hops != 0 || !unset4(p.GIAddr) {
		return malformed("relayed requests are not served")
	}
	if _, err := model.MACFromBytes(p.CHAddr[:]); err != nil {
		return malformed("chaddr is not a non-zero unicast Ethernet address")
	}
	if !clientMessage(p.MsgType) {
		return malformed("invalid client message type")
	}
	for _, a := range []netip.Addr{p.CIAddr, p.YIAddr, p.SIAddr, p.RequestedIP, p.ServerID} {
		if a.IsValid() && !a.Is4() {
			return malformed("non-IPv4 address field")
		}
	}
	if len(p.ClientID) > maxClientID {
		return malformed("client identifier too long")
	}
	return nil
}

func unicast4(a netip.Addr) bool {
	return set4(a) && !a.IsMulticast() && !a.IsLoopback() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func put4(b []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(b, v[:])
	}
}

func seconds(d time.Duration) uint32 { return uint32(d / time.Second) }

// MarshalReply encodes an OFFER, ACK or NAK. A NAK carries only the message
// type and server identifier, with yiaddr and ciaddr zero.
func (p *Packet) MarshalReply() ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil packet", ErrReply)
	}
	if p.MsgType != MsgOffer && p.MsgType != MsgAck && p.MsgType != MsgNak {
		return nil, fmt.Errorf("%w: message type %s", ErrReply, p.MsgType)
	}
	if _, err := model.MACFromBytes(p.CHAddr[:]); err != nil {
		return nil, fmt.Errorf("%w: chaddr", ErrReply)
	}
	if !unicast4(p.ServerID) {
		return nil, fmt.Errorf("%w: server identifier", ErrReply)
	}
	nak := p.MsgType == MsgNak
	if !nak {
		lease, t1, t2 := seconds(p.LeaseTime), seconds(p.Renewal), seconds(p.Rebind)
		if !unicast4(p.YIAddr) || !unicast4(p.Router) || !unicast4(p.DNS) ||
			(p.CIAddr.IsValid() && !p.CIAddr.Is4()) || p.SIAddr.IsValid() && !p.SIAddr.Is4() {
			return nil, fmt.Errorf("%w: address fields", ErrReply)
		}
		if p.LeaseTime < time.Second || p.LeaseTime >= 0xffffffff*time.Second || t1 < 1 || t1 >= t2 || t2 >= lease {
			return nil, fmt.Errorf("%w: lease timers", ErrReply)
		}
		if p.SubnetBits < 1 || p.SubnetBits > 30 {
			return nil, fmt.Errorf("%w: subnet mask", ErrReply)
		}
	}

	b := make([]byte, minPacket, minReply)
	b[0], b[1], b[2] = opReply, htypeEthernet, hlenEthernet
	binary.BigEndian.PutUint32(b[4:8], p.XID)
	binary.BigEndian.PutUint16(b[10:12], p.Flags)
	if !nak {
		put4(b[12:16], p.CIAddr)
		put4(b[16:20], p.YIAddr)
		put4(b[20:24], p.SIAddr)
	}
	copy(b[28:34], p.CHAddr[:])
	copy(b[headerLen:], magicCookie)

	opt := func(code byte, val ...byte) { b = append(append(b, code, byte(len(val))), val...) }
	opt4 := func(code byte, a netip.Addr) { v := a.As4(); opt(code, v[:]...) }
	optU32 := func(code byte, v uint32) { opt(code, byte(v>>24), byte(v>>16), byte(v>>8), byte(v)) }

	opt(optMessageType, byte(p.MsgType))
	opt4(optServerID, p.ServerID)
	if !nak {
		optU32(optLeaseTime, seconds(p.LeaseTime))
		optU32(optRenewal, seconds(p.Renewal))
		optU32(optRebind, seconds(p.Rebind))
		optU32(optSubnetMask, ^uint32(0)<<(32-p.SubnetBits))
		opt4(optRouter, p.Router)
		opt4(optDNS, p.DNS)
	}
	b = append(b, optEnd)
	for len(b) < minReply {
		b = append(b, optPad)
	}
	return b, nil
}
