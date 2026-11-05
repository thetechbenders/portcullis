package guestdns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	typeAAAA = 28
	typeTXT  = 16
	typeMX   = 15
	typeANY  = 255
	typeSOA  = 6
	classCH  = 3
	classANY = 255
)

var (
	gateway = netip.MustParseAddr("10.203.0.1")
	demo    = netip.MustParseAddr("198.18.0.2")
)

func testZone() Zone {
	return Zone{Records: map[string]netip.Addr{
		"portal.portcullis.test": gateway,
		"captive.apple.com":      gateway,
		"demo.portcullis.test":   demo,
	}, TTL: DefaultTTL}
}

func testResponder(t testing.TB) *Responder {
	t.Helper()
	r, err := NewResponder(testZone())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// wireName encodes a dotted name into uncompressed wire labels. Labels
// are taken verbatim (no case folding) so tests can exercise 0x20 echo.
func wireName(name string) []byte {
	var b []byte
	if name != "" && name != "." {
		for _, label := range strings.Split(name, ".") {
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	return append(b, 0)
}

// rawLabels encodes the given labels exactly, allowing '.' inside labels.
func rawLabels(labels ...string) []byte {
	var b []byte
	for _, label := range labels {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

type header struct {
	id, flags, qd, an, ns, ar uint16
}

func (h header) bytes() []byte {
	b := make([]byte, headerLen)
	for i, v := range []uint16{h.id, h.flags, h.qd, h.an, h.ns, h.ar} {
		binary.BigEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func parseHeader(t testing.TB, b []byte) header {
	t.Helper()
	if len(b) < headerLen {
		t.Fatalf("response shorter than a header: %d bytes", len(b))
	}
	var v [6]uint16
	for i := range v {
		v[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return header{v[0], v[1], v[2], v[3], v[4], v[5]}
}

// question builds a raw question section.
func question(name []byte, qtype, qclass uint16) []byte {
	b := append([]byte(nil), name...)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, qtype), qclass)
}

// query builds a standard query (opcode QUERY, RD set) for one question.
func query(id uint16, name string, qtype uint16) []byte {
	return append(header{id: id, flags: flagRD, qd: 1}.bytes(), question(wireName(name), qtype, classIN)...)
}

// optRR builds one EDNS(0) OPT record with the given RDATA.
func optRR(payload uint16, rdata []byte) []byte {
	b := []byte{0}
	b = binary.BigEndian.AppendUint16(b, typeOPT)
	b = binary.BigEndian.AppendUint16(b, payload)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

func withEDNS(q []byte, rdata []byte) []byte {
	q = append(append([]byte(nil), q...), optRR(1232, rdata)...)
	binary.BigEndian.PutUint16(q[10:12], 1)
	return q
}

// respond runs Respond and enforces the invariants every reply must hold:
// the amplification bound, ID copy, QR=1, and RA/TC/Z/AD/CD all zero.
func respond(t *testing.T, r *Responder, q []byte) (header, []byte) {
	t.Helper()
	orig := append([]byte(nil), q...)
	resp, ok := r.Respond(q)
	if !bytes.Equal(q, orig) {
		t.Fatal("Respond modified the query")
	}
	if !ok {
		t.Fatalf("query unexpectedly dropped: % x", q)
	}
	if len(resp) > len(q)+MaxResponseGrowth {
		t.Fatalf("amplification: %d-byte query produced %d-byte response", len(q), len(resp))
	}
	h := parseHeader(t, resp)
	if h.id != binary.BigEndian.Uint16(q[0:2]) {
		t.Fatalf("ID not copied: %#04x", h.id)
	}
	if h.flags&flagQR == 0 || h.flags&0x00F0 != 0 || h.flags&0x0200 != 0 {
		t.Fatalf("bad response flags %#04x (QR must be 1; RA, Z, AD, CD, TC must be 0)", h.flags)
	}
	if want := binary.BigEndian.Uint16(q[2:4]) & (opcodeMask | flagRD); h.flags&(opcodeMask|flagRD) != want {
		t.Fatalf("opcode/RD not copied: got %#04x want %#04x", h.flags&(opcodeMask|flagRD), want)
	}
	return h, resp
}

func rcode(h header) uint16 { return h.flags & 0x000F }

func TestRespondAHit(t *testing.T) {
	r := testResponder(t)
	for name, want := range map[string]netip.Addr{
		"portal.portcullis.test": gateway,
		"captive.apple.com":      gateway,
		"demo.portcullis.test":   demo,
	} {
		q := query(0xBEEF, name, typeA)
		h, resp := respond(t, r, q)
		if rcode(h) != rcodeNoError || h.flags&flagAA == 0 || h.qd != 1 || h.an != 1 || h.ns != 0 || h.ar != 0 {
			t.Fatalf("%s: header %+v", name, h)
		}
		if len(resp) != len(q)+answerLen {
			t.Fatalf("%s: response length %d", name, len(resp))
		}
		if !bytes.Equal(resp[headerLen:len(q)], q[headerLen:]) {
			t.Fatalf("%s: question not echoed", name)
		}
		ans := resp[len(q):]
		wantAns := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4}
		wantAns = append(wantAns, want.AsSlice()...)
		if !bytes.Equal(ans, wantAns) {
			t.Fatalf("%s: answer % x, want % x", name, ans, wantAns)
		}
	}
}

func TestRespondGoldenBytes(t *testing.T) {
	r := testResponder(t)
	q := query(0x1234, "portal.portcullis.test", typeA)
	resp, ok := r.Respond(q)
	if !ok {
		t.Fatal("dropped")
	}
	want := []byte{
		0x12, 0x34, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0, // ID, QR|AA|RD, QD=1 AN=1
		6, 'p', 'o', 'r', 't', 'a', 'l', 10, 'p', 'o', 'r', 't', 'c', 'u', 'l', 'l', 'i', 's', 4, 't', 'e', 's', 't', 0,
		0, 1, 0, 1, // A IN
		0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 10, 203, 0, 1,
	}
	if !bytes.Equal(resp, want) {
		t.Fatalf("golden mismatch\n got % x\nwant % x", resp, want)
	}
}

func TestRespondCaseInsensitiveEcho(t *testing.T) {
	r := testResponder(t)
	for _, name := range []string{"PoRtAl.PortCullis.TEST", "PORTAL.PORTCULLIS.TEST", "Captive.Apple.Com"} {
		q := query(7, name, typeA)
		h, resp := respond(t, r, q)
		if rcode(h) != rcodeNoError || h.an != 1 {
			t.Fatalf("%s: header %+v", name, h)
		}
		if !bytes.Equal(resp[headerLen:len(q)], q[headerLen:]) {
			t.Fatalf("%s: question case not preserved: % x", name, resp[headerLen:len(q)])
		}
		if !bytes.Contains(resp, []byte(strings.Split(name, ".")[0])) {
			t.Fatalf("%s: 0x20 label case lost", name)
		}
	}
}

func TestRespondNoData(t *testing.T) {
	r := testResponder(t)
	for _, qtype := range []uint16{typeAAAA, typeANY, typeTXT, typeMX, typeSOA, 0, 65535} {
		q := query(9, "portal.portcullis.test", qtype)
		h, resp := respond(t, r, q)
		if rcode(h) != rcodeNoError || h.flags&flagAA == 0 || h.qd != 1 || h.an != 0 || h.ns != 0 || h.ar != 0 {
			t.Fatalf("qtype %d: header %+v", qtype, h)
		}
		if !bytes.Equal(resp, append(resp[:headerLen:headerLen], q[headerLen:]...)) {
			t.Fatalf("qtype %d: NODATA must be header plus echoed question only", qtype)
		}
	}
}

func TestRespondRefusesOutOfZone(t *testing.T) {
	r := testResponder(t)
	cases := map[string][]byte{
		"unrelated":          wireName("example.com"),
		"subdomain":          wireName("x.portal.portcullis.test"),
		"parent":             wireName("portcullis.test"),
		"root":               wireName("."),
		"single label":       wireName("portal"),
		"trailing junk":      wireName("portal.portcullis.test.evil"),
		"dot inside a label": rawLabels("portal.portcullis", "test"),
		"all one label":      rawLabels("portal.portcullis.test"),
		"non-ascii":          rawLabels("portal\xc3", "portcullis", "test"),
		"nul in label":       rawLabels("portal\x00", "portcullis", "test"),
		"underscore":         wireName("_dns.resolver.arpa"),
		"version.bind":       wireName("version.bind"),
		"near miss":          wireName("portal.portcullis.tesu"),
	}
	for name, qname := range cases {
		for _, qtype := range []uint16{typeA, typeAAAA, typeANY} {
			q := append(header{id: 3, flags: flagRD, qd: 1}.bytes(), question(qname, qtype, classIN)...)
			h, resp := respond(t, r, q)
			if rcode(h) != rcodeRefused || h.flags&flagAA != 0 || h.qd != 1 || h.an != 0 {
				t.Fatalf("%s/%d: header %+v", name, qtype, h)
			}
			if !bytes.Equal(resp[headerLen:], q[headerLen:]) {
				t.Fatalf("%s/%d: REFUSED must echo the question", name, qtype)
			}
		}
	}
}

func TestRespondRefusesNonINClass(t *testing.T) {
	r := testResponder(t)
	for _, class := range []uint16{classCH, classANY, 4, 0} {
		q := append(header{id: 4, qd: 1}.bytes(), question(wireName("portal.portcullis.test"), typeA, class)...)
		h, _ := respond(t, r, q)
		if rcode(h) != rcodeRefused || h.an != 0 || h.flags&flagAA != 0 {
			t.Fatalf("class %d: header %+v", class, h)
		}
	}
}

func TestRespondNotImplemented(t *testing.T) {
	r := testResponder(t)
	for _, opcode := range []uint16{1 /* IQUERY */, 2 /* STATUS */, 4 /* NOTIFY */, 5 /* UPDATE */, 15} {
		q := query(5, "portal.portcullis.test", typeA)
		binary.BigEndian.PutUint16(q[2:4], opcode<<11|flagRD)
		h, resp := respond(t, r, q)
		if rcode(h) != rcodeNotImp || len(resp) != headerLen || h.qd != 0 || h.an != 0 || h.flags&flagAA != 0 {
			t.Fatalf("opcode %d: header %+v len %d", opcode, h, len(resp))
		}
		if (h.flags&opcodeMask)>>11 != opcode {
			t.Fatalf("opcode %d not echoed", opcode)
		}
	}
}

func TestRespondFormErr(t *testing.T) {
	r := testResponder(t)
	good := question(wireName("portal.portcullis.test"), typeA, classIN)
	long := make([]string, 0, 5)
	for range 5 {
		long = append(long, strings.Repeat("a", 63))
	}
	cases := map[string][]byte{
		"header only":           header{id: 1, qd: 0}.bytes(),
		"no question":           append(header{id: 1, qd: 0}.bytes(), good...),
		"two questions":         append(append(header{id: 1, qd: 2}.bytes(), good...), good...),
		"answer count":          append(header{id: 1, qd: 1, an: 1}.bytes(), good...),
		"authority count":       append(header{id: 1, qd: 1, ns: 1}.bytes(), good...),
		"two additional":        append(header{id: 1, qd: 1, ar: 2}.bytes(), good...),
		"max counts":            append(header{id: 1, qd: 0xFFFF, an: 0xFFFF, ns: 0xFFFF, ar: 0xFFFF}.bytes(), good...),
		"compression in name":   append(header{id: 1, qd: 1}.bytes(), 0xC0, 0x0C, 0, 1, 0, 1),
		"pointer after label":   append(header{id: 1, qd: 1}.bytes(), 6, 'p', 'o', 'r', 't', 'a', 'l', 0xC0, 0x0C, 0, 1, 0, 1),
		"extended label 0x40":   append(header{id: 1, qd: 1}.bytes(), 0x41, 'x', 0, 0, 1, 0, 1),
		"reserved label 0x80":   append(header{id: 1, qd: 1}.bytes(), 0x81, 'x', 0, 0, 1, 0, 1),
		"label overruns":        append(header{id: 1, qd: 1}.bytes(), 20, 'p', 'o', 'r'),
		"unterminated name":     append(header{id: 1, qd: 1}.bytes(), 3, 'c', 'o', 'm'),
		"missing qtype":         append(header{id: 1, qd: 1}.bytes(), wireName("portal.portcullis.test")...),
		"short qclass":          append(header{id: 1, qd: 1}.bytes(), append(wireName("portal.portcullis.test"), 0, 1, 0)...),
		"name over 255":         append(header{id: 1, qd: 1}.bytes(), question(wireName(strings.Join(long, ".")), typeA, classIN)...),
		"trailing bytes":        append(append(header{id: 1, qd: 1}.bytes(), good...), 0xDE, 0xAD),
		"ar=1 without record":   append(header{id: 1, qd: 1, ar: 1}.bytes(), good...),
		"additional not OPT":    append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), question(wireName("x.test"), typeA, classIN)...),
		"OPT with owner name":   append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), append(wireName("x"), optRR(512, nil)[1:]...)...),
		"OPT rdlen too long":    append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 9),
		"OPT truncated":         append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), 0, 0, 41, 2, 0),
		"OPT trailing":          append(append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), optRR(1232, nil)...), 0),
		"OPT bad option TLV":    append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), optRR(1232, []byte{0, 10, 0, 8, 1})...),
		"OPT short option head": append(append(header{id: 1, qd: 1, ar: 1}.bytes(), good...), optRR(1232, []byte{0, 10, 0})...),
	}
	for name, q := range cases {
		h, resp := respond(t, r, q)
		if rcode(h) != rcodeFormErr || len(resp) != headerLen || h.qd != 0 || h.an != 0 || h.ns != 0 || h.ar != 0 || h.flags&flagAA != 0 {
			t.Errorf("%s: header %+v len %d", name, h, len(resp))
		}
	}
}

func TestRespondNameLengthBoundary(t *testing.T) {
	// 255 wire bytes is the maximum; such a name is well formed (and
	// refused as out of zone), 256 is FORMERR.
	labels := []string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}
	name := wireName(strings.Join(labels, "."))
	if len(name) != 255 {
		t.Fatalf("test name is %d wire bytes", len(name))
	}
	q := append(header{id: 1, qd: 1}.bytes(), question(name, typeA, classIN)...)
	if h, _ := respond(t, r(t), q); rcode(h) != rcodeRefused {
		t.Fatalf("255-byte name: %+v", h)
	}
	labels[3] = strings.Repeat("d", 62)
	q = append(header{id: 1, qd: 1}.bytes(), question(wireName(strings.Join(labels, ".")), typeA, classIN)...)
	if h, _ := respond(t, r(t), q); rcode(h) != rcodeFormErr {
		t.Fatalf("256-byte name: %+v", h)
	}
}

func r(t *testing.T) *Responder { return testResponder(t) }

func TestRespondDrops(t *testing.T) {
	rr := testResponder(t)
	valid := query(1, "portal.portcullis.test", typeA)
	response := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(response[2:4], flagQR|flagAA)
	responseNotImp := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(responseNotImp[2:4], flagQR|2<<11)
	pad := MaxQueryBytes + 1 - len(valid) - 11 - 4
	oversized := withEDNS(valid, append([]byte{0, 12, byte(pad >> 8), byte(pad)}, make([]byte, pad)...))
	if len(oversized) != MaxQueryBytes+1 {
		t.Fatalf("oversized test query is %d bytes", len(oversized))
	}
	for name, q := range map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"11 bytes":       make([]byte, 11),
		"513 bytes":      oversized,
		"64 KiB":         make([]byte, 64<<10),
		"QR=1 response":  response,
		"QR=1 any op":    responseNotImp,
		"QR=1 truncated": {0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0},
	} {
		if resp, ok := rr.Respond(q); ok || resp != nil {
			t.Errorf("%s: expected silent drop, got % x", name, resp)
		}
	}
}

func TestRespondEDNSTolerated(t *testing.T) {
	rr := testResponder(t)
	cookie := []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	for name, rdata := range map[string][]byte{"no options": nil, "cookie": cookie} {
		q := withEDNS(query(11, "portal.portcullis.test", typeA), rdata)
		h, resp := respond(t, rr, q)
		if rcode(h) != rcodeNoError || h.an != 1 || h.ar != 0 {
			t.Fatalf("%s: header %+v", name, h)
		}
		plain, _ := rr.Respond(query(11, "portal.portcullis.test", typeA))
		if !bytes.Equal(resp, plain) {
			t.Fatalf("%s: EDNS query reply must equal the plain reply without OPT", name)
		}
	}
	q := withEDNS(query(12, "example.com", typeA), cookie)
	if h, resp := respond(t, rr, q); rcode(h) != rcodeRefused || h.ar != 0 || len(resp) >= len(q) {
		t.Fatalf("EDNS refused: %+v len %d", h, len(resp))
	}
}

func TestRespondMaximumSizeQuery(t *testing.T) {
	rr := testResponder(t)
	base := query(13, "portal.portcullis.test", typeA)
	pad := MaxQueryBytes - len(base) - 11 - 4
	q := withEDNS(base, append([]byte{0, 12, byte(pad >> 8), byte(pad)}, make([]byte, pad)...))
	if len(q) != MaxQueryBytes {
		t.Fatalf("query is %d bytes", len(q))
	}
	if h, _ := respond(t, rr, q); rcode(h) != rcodeNoError || h.an != 1 {
		t.Fatalf("512-byte query: %+v", h)
	}
}

func TestRespondCopiesRD(t *testing.T) {
	rr := testResponder(t)
	for _, flags := range []uint16{0, flagRD, flagRD | 0x0010 /* CD */ | 0x0020 /* AD */ | 0x0040 /* Z */ | 0x0200 /* TC */ | 0x0080 /* RA */} {
		q := query(14, "portal.portcullis.test", typeA)
		binary.BigEndian.PutUint16(q[2:4], flags)
		h, _ := respond(t, rr, q)
		if h.flags&flagRD != flags&flagRD || h.flags&0x0080 != 0 {
			t.Fatalf("query flags %#04x: response flags %#04x", flags, h.flags)
		}
	}
}

func TestRespondDoesNotAliasInput(t *testing.T) {
	rr := testResponder(t)
	q := query(15, "portal.portcullis.test", typeA)
	resp, _ := rr.Respond(q)
	snapshot := append([]byte(nil), resp...)
	for i := range q {
		q[i] = 0xFF
	}
	if !bytes.Equal(resp, snapshot) {
		t.Fatal("response aliases the query buffer")
	}
}

func TestRespondConcurrent(t *testing.T) {
	rr := testResponder(t)
	done := make(chan struct{})
	for g := range 16 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range 200 {
				q := query(uint16(g<<8|i), "Portal.Portcullis.Test", typeA)
				resp, ok := rr.Respond(q)
				if !ok || len(resp) != len(q)+answerLen || binary.BigEndian.Uint16(resp) != uint16(g<<8|i) {
					t.Errorf("goroutine %d query %d: bad reply", g, i)
					return
				}
			}
		}()
	}
	for range 16 {
		<-done
	}
}

func TestResponderTTL(t *testing.T) {
	z := testZone()
	z.TTL = 300 * time.Second
	rr, err := NewResponder(z)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := rr.Respond(query(1, "demo.portcullis.test", typeA))
	if ttl := binary.BigEndian.Uint32(resp[len(resp)-10:]); ttl != 300 {
		t.Fatalf("TTL %d", ttl)
	}
}

func FuzzRespond(f *testing.F) {
	f.Add(query(1, "portal.portcullis.test", typeA))
	f.Add(query(2, "PoRtAl.portcullis.TEST", typeAAAA))
	f.Add(query(3, "example.com", typeANY))
	f.Add(withEDNS(query(4, "captive.apple.com", typeA), []byte{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}))
	f.Add(append(header{id: 5, qd: 1}.bytes(), 0xC0, 0x0C, 0, 1, 0, 1))
	f.Add(header{id: 6, flags: 2 << 11, qd: 1}.bytes())
	f.Add(append(header{id: 7, qd: 1}.bytes(), rawLabels("portal.portcullis", "test")...))
	f.Add([]byte{})
	rr, err := NewResponder(testZone())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, q []byte) {
		orig := append([]byte(nil), q...)
		resp, ok := rr.Respond(q)
		if !bytes.Equal(q, orig) {
			t.Fatal("Respond modified its input")
		}
		if !ok {
			if resp != nil {
				t.Fatal("dropped query returned bytes")
			}
			if len(q) >= headerLen && len(q) <= MaxQueryBytes && q[2]&0x80 == 0 {
				t.Fatalf("well-sized query with QR=0 dropped: % x", q)
			}
			return
		}
		if len(q) < headerLen || len(q) > MaxQueryBytes || q[2]&0x80 != 0 {
			t.Fatalf("query that must be dropped was answered: % x", q)
		}
		if len(resp) > len(q)+MaxResponseGrowth || len(resp) < headerLen {
			t.Fatalf("response size %d for %d-byte query", len(resp), len(q))
		}
		if !bytes.Equal(resp[:2], q[:2]) || resp[2]&0x80 == 0 || resp[2]&0x02 != 0 || resp[3]&0xF0 != 0 {
			t.Fatalf("bad header % x for query % x", resp[:headerLen], q)
		}
		an := int(binary.BigEndian.Uint16(resp[6:8]))
		if an > 1 || binary.BigEndian.Uint16(resp[8:10]) != 0 || binary.BigEndian.Uint16(resp[10:12]) != 0 {
			t.Fatalf("unexpected record counts % x", resp[:headerLen])
		}
		if binary.BigEndian.Uint16(resp[4:6]) == 1 {
			qsec := resp[headerLen : len(resp)-an*answerLen]
			if !bytes.Equal(qsec, q[headerLen:headerLen+len(qsec)]) {
				t.Fatal("question not echoed verbatim")
			}
		} else if len(resp) != headerLen {
			t.Fatal("reply without a question must be a bare header")
		}
		again, ok2 := rr.Respond(q)
		if !ok2 || !bytes.Equal(again, resp) {
			t.Fatal("Respond is not deterministic")
		}
	})
}
