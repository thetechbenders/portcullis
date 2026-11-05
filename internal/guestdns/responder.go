// Package guestdns is the static, authoritative DNS responder that the
// unprivileged portal runs on the gateway's guest address.
//
// It answers A queries for the portal, captive-probe and configured demo
// names from a fixed in-memory zone and nothing else. It never recurses or
// forwards (RA is always 0), never returns IPv6 data, and answers REFUSED
// for every name outside the zone. A response is never larger than the
// query plus one 16-byte answer record, so the responder cannot be used to
// amplify traffic, and Serve rate limits replies globally and per source.
//
// Answering a name is not authorization. The kernel guard decides which
// guests may reach this responder at all (bound_v4) and where any guest may
// go afterwards; this package holds no privileges and makes no grant
// decisions.
package guestdns

import (
	"encoding/binary"
	"sync/atomic"
	"time"
)

const (
	// MaxQueryBytes is the classic DNS-over-UDP message limit. Larger
	// datagrams are dropped, never truncated and parsed.
	MaxQueryBytes = 512
	// MaxResponseGrowth is the most a response may exceed its query by:
	// exactly one compressed A record. The question is echoed, never
	// expanded, and an EDNS OPT record in the query is not echoed back.
	MaxResponseGrowth = answerLen

	headerLen  = 12
	answerLen  = 16 // pointer(2) type(2) class(2) ttl(4) rdlength(2) rdata(4)
	maxWireLen = 255

	flagQR      = 0x8000
	opcodeMask  = 0x7800
	flagAA      = 0x0400
	flagRD      = 0x0100
	opcodeQuery = 0

	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeNotImp   = 4
	rcodeRefused  = 5
	typeA         = 1
	typeOPT       = 41
	classIN       = 1
	pointerToName = 0xC000 | headerLen
)

// Responder answers queries from an immutable zone. Respond is safe for
// concurrent use; each Serve call keeps its own rate-limiter state.
type Responder struct {
	records map[string][4]byte
	ttl     uint32

	// now and limits are fixed at construction; tests in this package
	// replace them before calling Serve.
	now    func() time.Time
	limits limits
	stats  stats
}

// stats are observability counters; they never contain query data.
type stats struct {
	received, dropped, limited, answered, writeErrors atomic.Uint64
}

// NewResponder validates z and copies it, so later changes to z.Records
// do not affect the responder.
func NewResponder(z Zone) (*Responder, error) {
	records, ttl, err := z.validate()
	if err != nil {
		return nil, err
	}
	return &Responder{records: records, ttl: ttl, now: time.Now, limits: defaultLimits}, nil
}

// Respond computes the reply to one query datagram. It is pure: it does
// not retain or modify query and always returns a freshly allocated
// response. ok=false means the datagram must be dropped silently.
//
// Datagrams outside 12..512 bytes and messages with QR=1 are dropped (a
// response to a response could set up a reflection loop between two
// servers). Every other message gets exactly one reply whose size is at
// most len(query)+MaxResponseGrowth.
func (r *Responder) Respond(query []byte) (resp []byte, ok bool) {
	if len(query) < headerLen || len(query) > MaxQueryBytes {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&flagQR != 0 {
		return nil, false
	}
	if (flags&opcodeMask)>>11 != opcodeQuery {
		return headerOnly(query, rcodeNotImp), true
	}
	qd := binary.BigEndian.Uint16(query[4:6])
	an := binary.BigEndian.Uint16(query[6:8])
	ns := binary.BigEndian.Uint16(query[8:10])
	ar := binary.BigEndian.Uint16(query[10:12])
	if qd != 1 || an != 0 || ns != 0 || ar > 1 {
		return headerOnly(query, rcodeFormErr), true
	}
	key, ldh, end, ok := questionName(query)
	if !ok || end+4 > len(query) {
		return headerOnly(query, rcodeFormErr), true
	}
	qtype := binary.BigEndian.Uint16(query[end : end+2])
	qclass := binary.BigEndian.Uint16(query[end+2 : end+4])
	qEnd := end + 4
	if ar == 1 {
		if !validOPT(query[qEnd:]) {
			return headerOnly(query, rcodeFormErr), true
		}
	} else if qEnd != len(query) {
		return headerOnly(query, rcodeFormErr), true
	}
	if qclass != classIN {
		return r.reply(query, qEnd, rcodeRefused, false, nil), true
	}
	var addr [4]byte
	found := false
	if ldh {
		addr, found = r.records[string(key)]
	}
	if !found {
		// Not a resolver: names outside the static zone are refused,
		// never forwarded and never answered NXDOMAIN on someone else's
		// behalf.
		return r.reply(query, qEnd, rcodeRefused, false, nil), true
	}
	if qtype != typeA {
		// NODATA for AAAA, ANY and everything else: guests receive no
		// IPv6 service and the zone holds nothing but A data.
		return r.reply(query, qEnd, rcodeNoError, true, nil), true
	}
	return r.reply(query, qEnd, rcodeNoError, true, &addr), true
}

// questionName parses the uncompressed question name starting after the
// header. key is the ASCII-lowercased presentation form; ldh reports
// whether every label consists only of [a-z0-9-] after folding, because
// only such names can be in the zone. Checking ldh also prevents a single
// wire label containing a '.' byte from impersonating a multi-label name.
// ok is false for malformed names: compression pointers or extended label
// types (the question must be self-contained), overruns, and names longer
// than 255 wire bytes.
func questionName(msg []byte) (key []byte, ldh bool, end int, ok bool) {
	off, wire := headerLen, 0
	ldh = true
	key = make([]byte, 0, 64)
	for {
		if off >= len(msg) {
			return nil, false, 0, false
		}
		n := int(msg[off])
		off++
		if n&0xC0 != 0 {
			return nil, false, 0, false
		}
		if n == 0 {
			return key, ldh, off, true
		}
		wire += 1 + n
		if wire+1 > maxWireLen || off+n > len(msg) {
			return nil, false, 0, false
		}
		if len(key) > 0 {
			key = append(key, '.')
		}
		for _, c := range msg[off : off+n] {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				ldh = false
			}
			key = append(key, c)
		}
		off += n
	}
}

// validOPT reports whether b is exactly one well-framed EDNS(0) OPT
// record: root owner name, type OPT, RDLENGTH consuming the rest of the
// message, and option TLVs that exactly fill RDATA. Its contents are then
// ignored; the reply carries no OPT, as from a server without EDNS.
func validOPT(b []byte) bool {
	if len(b) < 11 || b[0] != 0 || binary.BigEndian.Uint16(b[1:3]) != typeOPT {
		return false
	}
	rdata := b[11:]
	if int(binary.BigEndian.Uint16(b[9:11])) != len(rdata) {
		return false
	}
	for len(rdata) > 0 {
		if len(rdata) < 4 {
			return false
		}
		n := int(binary.BigEndian.Uint16(rdata[2:4]))
		if 4+n > len(rdata) {
			return false
		}
		rdata = rdata[4+n:]
	}
	return true
}

// responseFlags copies only the opcode and RD from the query. RA, TC, AD,
// CD and Z are always zero.
func responseFlags(query []byte, rcode uint16, aa bool) uint16 {
	flags := flagQR | binary.BigEndian.Uint16(query[2:4])&(opcodeMask|flagRD) | rcode
	if aa {
		flags |= flagAA
	}
	return flags
}

// headerOnly is the reply for messages whose question cannot be trusted
// (FORMERR) or whose opcode is not implemented (NOTIMP): a bare header with
// all section counts zero, never larger than the query.
func headerOnly(query []byte, rcode uint16) []byte {
	resp := make([]byte, headerLen)
	copy(resp[0:2], query[0:2])
	binary.BigEndian.PutUint16(resp[2:4], responseFlags(query, rcode, false))
	return resp
}

// reply echoes the question bytes exactly as received (preserving 0x20
// case randomization) and appends at most one A record that points back at
// the question name.
func (r *Responder) reply(query []byte, qEnd int, rcode uint16, aa bool, answer *[4]byte) []byte {
	size := qEnd
	if answer != nil {
		size += answerLen
	}
	resp := make([]byte, size)
	copy(resp[0:2], query[0:2])
	binary.BigEndian.PutUint16(resp[2:4], responseFlags(query, rcode, aa))
	binary.BigEndian.PutUint16(resp[4:6], 1)
	copy(resp[headerLen:qEnd], query[headerLen:qEnd])
	if answer != nil {
		binary.BigEndian.PutUint16(resp[6:8], 1)
		a := resp[qEnd:]
		binary.BigEndian.PutUint16(a[0:2], pointerToName)
		binary.BigEndian.PutUint16(a[2:4], typeA)
		binary.BigEndian.PutUint16(a[4:6], classIN)
		binary.BigEndian.PutUint32(a[6:10], r.ttl)
		binary.BigEndian.PutUint16(a[10:12], 4)
		copy(a[12:16], answer[:])
	}
	return resp
}
