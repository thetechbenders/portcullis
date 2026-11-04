package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/thetechbenders/portcullis/internal/model"
)

const (
	maxGuardJSONBytes   = 4 << 20
	maxRulesetJSONBytes = 8 << 20
	maxJSONDepth        = 64
)

func attestErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrGuardAttestation, fmt.Sprintf(format, args...))
}

// parseStrictJSON decodes into generic values (numbers as json.Number),
// rejecting duplicate object keys, excessive nesting and trailing data. nft
// 1.0.9 silently truncates JSON in some states and still exits 0, so any
// parse failure must be an attestation failure.
func parseStrictJSON(data []byte, limit int) (any, error) {
	if len(data) == 0 || len(data) > limit {
		return nil, attestErr("missing or oversized listing")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseJSONValue(dec, 0)
	if err != nil {
		return nil, attestErr("decode: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, attestErr("trailing content")
	}
	return v, nil
}

func parseJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				if _, dup := obj[key]; dup {
					return nil, errors.New("duplicate object key")
				}
				if obj[key], err = parseJSONValue(dec, depth+1); err != nil {
					return nil, err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return arr, nil
		}
		return nil, errors.New("unexpected delimiter")
	case string, json.Number, bool, nil:
		return t, nil
	}
	return nil, errors.New("unexpected token")
}

func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	return false
}

type nftObject struct {
	kind string
	body map[string]any
}

// decodeListing returns the objects of an nft -j listing after its single
// leading metainfo (schema version 1 only).
func decodeListing(data []byte, limit int) ([]nftObject, error) {
	v, err := parseStrictJSON(data, limit)
	if err != nil {
		return nil, err
	}
	top, ok := v.(map[string]any)
	if !ok || len(top) != 1 {
		return nil, attestErr("listing must be a single nftables object")
	}
	list, ok := top["nftables"].([]any)
	if !ok || len(list) == 0 {
		return nil, attestErr("missing nftables array")
	}
	objs := make([]nftObject, 0, len(list))
	for i, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok || len(entry) != 1 {
			return nil, attestErr("invalid listing element")
		}
		for kind, payload := range entry {
			body, ok := payload.(map[string]any)
			if !ok {
				return nil, attestErr("invalid %.32q object", kind)
			}
			if kind == "metainfo" {
				if i != 0 || !jsonEqual(body["json_schema_version"], json.Number("1")) {
					return nil, attestErr("unexpected metainfo")
				}
				continue
			}
			if i == 0 {
				return nil, attestErr("missing metainfo")
			}
			objs = append(objs, nftObject{kind, body})
		}
	}
	return objs, nil
}

func exactKeys(o map[string]any, required []string, optional ...string) bool {
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	for k := range o {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return false
		}
	}
	return true
}

func uintValue(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	return u, err == nil
}

func secondsValue(v any) (time.Duration, bool) {
	u, ok := uintValue(v)
	if !ok || u > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, false
	}
	return time.Duration(u) * time.Second, true
}

// VerifyGuardJSON attests "nft -j list table inet portcullis_guard" output
// against the exact guard for c and returns its elements and counters.
func VerifyGuardJSON(data []byte, c GuardConfig) (model.KernelState, error) {
	if err := c.Validate(); err != nil {
		return model.KernelState{}, fmt.Errorf("%w: %w", ErrGuardAttestation, err)
	}
	objs, err := decodeListing(data, maxGuardJSONBytes)
	if err != nil {
		return model.KernelState{}, err
	}
	return verifyGuardObjects(objs, c)
}

func verifyGuardObjects(objs []nftObject, c GuardConfig) (model.KernelState, error) {
	var state model.KernelState
	byChain := map[string][]guardRule{}
	for _, r := range guardRules(c) {
		byChain[r.chain] = append(byChain[r.chain], r)
	}
	next := map[string]int{}
	seenTable := false
	seenSets := map[string]bool{}
	seenChains := map[string]bool{}
	for _, o := range objs {
		b := o.body
		if b["family"] != "inet" || (o.kind != "table" && b["table"] != GuardTable) {
			return state, attestErr("object outside inet %s", GuardTable)
		}
		if _, ok := uintValue(b["handle"]); !ok {
			return state, attestErr("missing handle on %.32q", o.kind)
		}
		switch o.kind {
		case "table":
			// No flags at all: dormant, owner or persist all change semantics.
			if seenTable || b["name"] != GuardTable || !exactKeys(b, []string{"family", "name", "handle"}) {
				return state, attestErr("dormant, flagged or duplicate table")
			}
			seenTable = true
		case "set":
			if !exactKeys(b, []string{"family", "name", "table", "type", "handle", "size", "flags"}, "elem") {
				return state, attestErr("unexpected set properties")
			}
			i := slices.IndexFunc(guardSets, func(s guardSet) bool { return b["name"] == s.name })
			if i < 0 || seenSets[guardSets[i].name] {
				return state, attestErr("unexpected or duplicate set")
			}
			spec := guardSets[i]
			seenSets[spec.name] = true
			if !jsonEqual(b["type"], spec.typeJSON) || !jsonEqual(b["size"], jnum(SetSize)) ||
				!jsonEqual(b["flags"], []any{"timeout"}) {
				return state, attestErr("wrong type, size or flags for set %s", spec.name)
			}
			var elems []model.Element
			if raw, ok := b["elem"]; ok {
				var err error
				if elems, err = parseElements(raw, spec, c); err != nil {
					return state, err
				}
			}
			switch spec.name {
			case SetBound:
				state.Bound = elems
			case SetGranted:
				state.Granted = elems
			default:
				state.GrantedDst = elems
			}
		case "chain":
			i := slices.IndexFunc(guardChains, func(ch struct{ name, hook string }) bool { return b["name"] == ch.name })
			if i < 0 || seenChains[guardChains[i].name] {
				return state, attestErr("unexpected or duplicate chain")
			}
			ch := guardChains[i]
			seenChains[ch.name] = true
			want := map[string]any{
				"family": "inet", "table": GuardTable, "name": ch.name, "handle": b["handle"],
				"type": "filter", "hook": ch.hook, "prio": jnum(guardPriority), "policy": "accept",
			}
			if !jsonEqual(b, want) {
				return state, attestErr("wrong hook, type, priority or policy for chain %s", ch.name)
			}
		case "rule":
			if !exactKeys(b, []string{"family", "table", "chain", "handle", "comment", "expr"}) {
				return state, attestErr("unexpected rule properties")
			}
			chain, _ := b["chain"].(string)
			rules, ok := byChain[chain]
			if !ok {
				return state, attestErr("rule in unexpected chain")
			}
			if next[chain] >= len(rules) {
				return state, attestErr("extra rule in chain %s", chain)
			}
			want := rules[next[chain]]
			next[chain]++
			counter, err := verifyRule(b, want)
			if err != nil {
				return state, err
			}
			state.Counters = append(state.Counters, counter)
		default:
			return state, attestErr("unexpected %.32q object", o.kind)
		}
	}
	if !seenTable || len(seenSets) != len(guardSets) || len(seenChains) != len(guardChains) {
		return state, attestErr("missing table, set or chain")
	}
	for chain, rules := range byChain {
		if next[chain] != len(rules) {
			return state, attestErr("missing rule in chain %s", chain)
		}
	}
	return state, nil
}

// verifyRule compares one listed rule with its specification. Counter
// values are read; handles are ignored; everything else must match exactly.
func verifyRule(b map[string]any, want guardRule) (model.Counter, error) {
	fail := func(what string) (model.Counter, error) {
		return model.Counter{}, attestErr("rule %s (expected position): %s", want.comment, what)
	}
	if b["comment"] != want.comment {
		return fail("wrong rule or order")
	}
	expr, ok := b["expr"].([]any)
	if !ok || len(expr) != len(want.terms)+2 {
		return fail("wrong statement count")
	}
	for i, term := range want.terms {
		if term.rangeSet {
			if !protectedEqual(expr[i], term.expr) {
				return fail("protected destinations differ")
			}
		} else if !jsonEqual(expr[i], term.expr) {
			return fail("match differs")
		}
	}
	wrap, ok := expr[len(want.terms)].(map[string]any)
	counter, _ := wrap["counter"].(map[string]any)
	if !ok || len(wrap) != 1 || !exactKeys(counter, []string{"packets", "bytes"}) {
		return fail("missing counter")
	}
	packets, ok1 := uintValue(counter["packets"])
	byteCount, ok2 := uintValue(counter["bytes"])
	if !ok1 || !ok2 {
		return fail("malformed counter")
	}
	if !jsonEqual(expr[len(want.terms)+1], map[string]any{want.verdict: nil}) {
		return fail("wrong verdict")
	}
	return model.Counter{Rule: want.comment, Packets: packets, Bytes: byteCount}, nil
}

type addrRange struct{ lo, hi uint32 }

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func parseV4(v any) (netip.Addr, bool) {
	s, ok := v.(string)
	if !ok {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Is4()
}

// rangeEntry converts one nft interval-set entry (prefix, range or bare
// address) into an inclusive IPv4 range.
func rangeEntry(v any) (addrRange, bool) {
	if a, ok := parseV4(v); ok {
		return addrRange{u32(a), u32(a)}, true
	}
	o, ok := v.(map[string]any)
	if !ok || len(o) != 1 {
		return addrRange{}, false
	}
	if p, ok := o["prefix"].(map[string]any); ok && exactKeys(p, []string{"addr", "len"}) {
		a, ok := parseV4(p["addr"])
		bits, ok2 := uintValue(p["len"])
		if !ok || !ok2 || bits > 32 {
			return addrRange{}, false
		}
		pfx := netip.PrefixFrom(a, int(bits))
		if pfx != pfx.Masked() {
			return addrRange{}, false
		}
		host := uint32((uint64(1) << (32 - bits)) - 1)
		return addrRange{u32(a), u32(a) | host}, true
	}
	if r, ok := o["range"].([]any); ok && len(r) == 2 {
		lo, ok1 := parseV4(r[0])
		hi, ok2 := parseV4(r[1])
		if ok1 && ok2 && !hi.Less(lo) {
			return addrRange{u32(lo), u32(hi)}, true
		}
	}
	return addrRange{}, false
}

// rangeSet normalizes the right-hand side of an "ip daddr" match into
// sorted, merged ranges.
func rangeSet(v any) ([]addrRange, bool) {
	entries := []any{v}
	if o, ok := v.(map[string]any); ok && len(o) == 1 {
		if set, ok := o["set"].([]any); ok {
			entries = set
		}
	}
	if len(entries) == 0 || len(entries) > 4096 {
		return nil, false
	}
	rs := make([]addrRange, 0, len(entries))
	for _, e := range entries {
		r, ok := rangeEntry(e)
		if !ok {
			return nil, false
		}
		rs = append(rs, r)
	}
	slices.SortFunc(rs, func(a, b addrRange) int {
		if a.lo != b.lo {
			return cmpU32(a.lo, b.lo)
		}
		return cmpU32(a.hi, b.hi)
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi || r.lo == last.hi+1 {
			last.hi = max(last.hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out, true
}

func cmpU32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func protectedEqual(observed, expected any) bool {
	split := func(v any) (map[string]any, any, bool) {
		w, ok := v.(map[string]any)
		m, ok2 := w["match"].(map[string]any)
		if !ok || !ok2 || len(w) != 1 || !exactKeys(m, []string{"op", "left", "right"}) {
			return nil, nil, false
		}
		head := map[string]any{"op": m["op"], "left": m["left"]}
		return head, m["right"], true
	}
	oh, or, ok1 := split(observed)
	eh, er, ok2 := split(expected)
	if !ok1 || !ok2 || !jsonEqual(oh, eh) {
		return false
	}
	ors, ok1 := rangeSet(or)
	ers, ok2 := rangeSet(er)
	return ok1 && ok2 && slices.Equal(ors, ers)
}

// validGuestAddr is shared by the element renderers and the element parser,
// so every element attestation reports can also be removed by a renderer.
func validGuestAddr(c GuardConfig, ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() &&
		ip != netip.AddrFrom4([4]byte{255, 255, 255, 255}) && ip != c.GatewayV4
}

// parseElements reads a set's "elem" array. A bare value (no wrapper) is an
// element WITHOUT a kernel timeout and is reported with Timeout 0 so the
// controller deletes it; malformed values fail attestation.
func parseElements(raw any, spec guardSet, c GuardConfig) ([]model.Element, error) {
	arr, ok := raw.([]any)
	if !ok || len(arr) > SetSize {
		return nil, attestErr("malformed or oversized elements in %s", spec.name)
	}
	type key struct {
		addr netip.Addr
		mac  model.MAC
	}
	seen := map[key]bool{}
	out := make([]model.Element, 0, len(arr))
	for _, item := range arr {
		var e model.Element
		val := item
		if o, ok := item.(map[string]any); ok {
			if inner, wrapped := o["elem"]; wrapped {
				w, ok := inner.(map[string]any)
				if !ok || len(o) != 1 || !exactKeys(w, []string{"val"}, "timeout", "expires") {
					return nil, attestErr("malformed element wrapper in %s", spec.name)
				}
				val = w["val"]
				for name, dst := range map[string]*time.Duration{"timeout": &e.Timeout, "expires": &e.Expires} {
					if v, present := w[name]; present {
						if *dst, ok = secondsValue(v); !ok {
							return nil, attestErr("malformed element %s in %s", name, spec.name)
						}
					}
				}
				if e.Timeout > 0 && e.Expires > e.Timeout {
					return nil, attestErr("element expires after its timeout in %s", spec.name)
				}
			}
		}
		var addrValue any = val
		if spec.concat {
			o, ok := val.(map[string]any)
			parts, ok2 := o["concat"].([]any)
			if !ok || !ok2 || len(o) != 1 || len(parts) != 2 {
				return nil, attestErr("malformed element value in %s", spec.name)
			}
			macText, ok := parts[1].(string)
			if !ok {
				return nil, attestErr("malformed element MAC in %s", spec.name)
			}
			mac, err := model.ParseMAC(macText)
			if err != nil {
				return nil, attestErr("invalid element MAC in %s", spec.name)
			}
			e.MAC, addrValue = mac, parts[0]
		}
		addr, ok := parseV4(addrValue)
		if !ok || !validGuestAddr(c, addr) {
			return nil, attestErr("invalid element address in %s", spec.name)
		}
		e.Addr = addr
		k := key{e.Addr, e.MAC}
		if seen[k] {
			return nil, attestErr("duplicate element in %s", spec.name)
		}
		seen[k] = true
		out = append(out, e)
	}
	return out, nil
}
