package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// ErrGuardAttestation indicates that observed nftables state is not the exact
// expected deny-only Portcullis guard. A controller MUST NOT treat this as
// authorization to proceed. This validator does no network or kernel I/O.
var ErrGuardAttestation = errors.New("portcullis guard attestation failed")

const guardTable = "portcullis_guard"

// VerifyDenyGuardJSON validates the observed nft -j list table inet
// portcullis_guard output. It fails on dormant tables, unhooked/wrong-hook
// chains, wrong priority/policy, unexpected owned objects, or unexpected
// rules. Counters and rule handles are intentionally ignored.
//
// This is a snapshot check only. It is NOT sufficient to guard a production
// install: a controller must own and verify the full packet path, interface
// identity, persistence, topology, offloads, and concurrent changes.
func VerifyDenyGuardJSON(data []byte, guest string) error {
	if !safeInterface.MatchString(guest) {
		return ErrGuestInterface
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return fmt.Errorf("%w: missing or oversized ruleset", ErrGuardAttestation)
	}
	if err := rejectDuplicateGuardJSON(data); err != nil {
		return fmt.Errorf("%w: invalid or ambiguous JSON: %v", ErrGuardAttestation, err)
	}
	// Go's struct decoder accepts case-insensitive and Unicode-folded field
	// names. An exact-key map is required so alternate top-level spellings
	// cannot replace a legitimate nftables listing.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrGuardAttestation, err)
	}
	rawListing, ok := document["nftables"]
	if len(document) != 1 || !ok {
		return fmt.Errorf("%w: expected exactly one literal nftables key", ErrGuardAttestation)
	}
	var listing []json.RawMessage
	if err := json.Unmarshal(rawListing, &listing); err != nil || len(listing) == 0 {
		return fmt.Errorf("%w: missing or malformed nftables listing", ErrGuardAttestation)
	}
	seenTable := false
	chains := map[string]bool{}
	rules := map[string]bool{}
	expected := map[string]struct {
		chain string
		iface string
		key   string
	}{
		"guest-input":   {"guest_input", guest, "iifname"},
		"guest-egress":  {"guest_forward", guest, "iifname"},
		"guest-ingress": {"guest_forward", guest, "oifname"},
	}
	for _, raw := range listing {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil || len(entry) != 1 {
			return fmt.Errorf("%w: invalid listing element", ErrGuardAttestation)
		}
		for kind, payload := range entry {
			if err := verifyDenyObjectFields(kind, payload); err != nil {
				return err
			}
			if kind == "metainfo" {
				continue
			}
			var o struct {
				Family  string           `json:"family"`
				Table   string           `json:"table"`
				Name    string           `json:"name"`
				Chain   string           `json:"chain"`
				Type    string           `json:"type"`
				Hook    string           `json:"hook"`
				Prio    json.RawMessage  `json:"prio"`
				Policy  string           `json:"policy"`
				Flags   []string         `json:"flags"`
				Comment string           `json:"comment"`
				Expr    []map[string]any `json:"expr"`
			}
			if err := json.Unmarshal(payload, &o); err != nil {
				return fmt.Errorf("%w: invalid %s object", ErrGuardAttestation, kind)
			}
			if o.Family != "inet" || (kind != "table" && o.Table != guardTable) {
				return fmt.Errorf("%w: unexpected object scope", ErrGuardAttestation)
			}
			switch kind {
			case "table":
				if o.Name != guardTable || seenTable || len(o.Flags) != 0 {
					return fmt.Errorf("%w: missing ownership or dormant/duplicate table", ErrGuardAttestation)
				}
				seenTable = true
			case "chain":
				if chains[o.Name] {
					return fmt.Errorf("%w: duplicate chain %q", ErrGuardAttestation, o.Name)
				}
				hook := ""
				switch o.Name {
				case "guest_input":
					hook = "input"
				case "guest_forward":
					hook = "forward"
				default:
					return fmt.Errorf("%w: unexpected chain %q", ErrGuardAttestation, o.Name)
				}
				var priority int
				if err := json.Unmarshal(o.Prio, &priority); err != nil || priority != -50 ||
					o.Type != "filter" || o.Hook != hook || o.Policy != "accept" {
					return fmt.Errorf("%w: wrong hook/type/priority/policy for %s", ErrGuardAttestation, o.Name)
				}
				chains[o.Name] = true
			case "rule":
				exp, ok := expected[o.Comment]
				if !ok || rules[o.Comment] || o.Chain != exp.chain || len(o.Expr) != 3 {
					return fmt.Errorf("%w: unexpected or duplicate rule %q", ErrGuardAttestation, o.Comment)
				}
				wantMatch := map[string]any{
					"match": map[string]any{
						"op":    "==",
						"left":  map[string]any{"meta": map[string]any{"key": exp.key}},
						"right": exp.iface,
					},
				}
				if !reflect.DeepEqual(o.Expr[0], wantMatch) {
					return fmt.Errorf("%w: incorrect interface match %q", ErrGuardAttestation, o.Comment)
				}
				counter, ok := o.Expr[1]["counter"].(map[string]any)
				if !ok || len(o.Expr[1]) != 1 || len(counter) != 2 {
					return fmt.Errorf("%w: missing counter %q", ErrGuardAttestation, o.Comment)
				}
				for _, key := range []string{"packets", "bytes"} {
					value, ok := counter[key].(float64)
					if !ok || value < 0 || value > 9007199254740991 || value != float64(uint64(value)) {
						return fmt.Errorf("%w: malformed %s counter %q", ErrGuardAttestation, key, o.Comment)
					}
				}
				if value, ok := o.Expr[2]["drop"]; !ok || value != nil || len(o.Expr[2]) != 1 {
					return fmt.Errorf("%w: missing drop verdict %q", ErrGuardAttestation, o.Comment)
				}
				rules[o.Comment] = true
			default:
				return fmt.Errorf("%w: unexpected owned object %q", ErrGuardAttestation, kind)
			}
		}
	}
	if !seenTable || len(chains) != 2 || !chains["guest_input"] || !chains["guest_forward"] || len(rules) != len(expected) {
		return fmt.Errorf("%w: missing required chain or rule", ErrGuardAttestation)
	}
	return nil
}

// rejectDuplicateGuardJSON rejects ambiguous keys at every nesting level,
// including inside match expressions that would otherwise decode last-wins.
// A depth bound protects the verifier from attacker-controlled nested input.
func rejectDuplicateGuardJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds limit")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				t, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := t.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or malformed JSON object key %q", key)
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return nil
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

// verifyDenyObjectFields rejects unrecognized or wrongly typed payload
// attributes instead of silently ignoring a second, potentially permissive
// interpretation of kernel state. Handles are informational only.
func verifyDenyObjectFields(kind string, payload json.RawMessage) error {
	fields := map[string]json.RawMessage{}
	if len(payload) == 0 || payload[0] != '{' || json.Unmarshal(payload, &fields) != nil {
		return fmt.Errorf("%w: malformed %s object", ErrGuardAttestation, kind)
	}
	var allowed, required []string
	switch kind {
	case "metainfo":
		allowed = []string{"version", "release_name", "json_schema_version"}
	case "table":
		allowed = []string{"family", "name", "flags", "handle"}
		required = []string{"family", "name"}
	case "chain":
		allowed = []string{"family", "table", "name", "type", "hook", "prio", "policy", "handle"}
		required = []string{"family", "table", "name", "type", "hook", "prio", "policy"}
	case "rule":
		allowed = []string{"family", "table", "chain", "comment", "expr", "handle"}
		required = []string{"family", "table", "chain", "comment", "expr"}
	default:
		return fmt.Errorf("%w: unexpected object %q", ErrGuardAttestation, kind)
	}
	permitted := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		permitted[k] = true
	}
	for k, v := range fields {
		if !permitted[k] || string(v) == "null" {
			return fmt.Errorf("%w: unexpected or null %s field %q", ErrGuardAttestation, kind, k)
		}
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return fmt.Errorf("%w: missing %s field %q", ErrGuardAttestation, kind, k)
		}
	}
	if raw, ok := fields["handle"]; ok {
		var handle uint64
		if json.Unmarshal(raw, &handle) != nil {
			return fmt.Errorf("%w: invalid handle on %s", ErrGuardAttestation, kind)
		}
	}
	if raw, ok := fields["flags"]; ok {
		var flags []string
		if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &flags) != nil {
			return fmt.Errorf("%w: invalid table flags", ErrGuardAttestation)
		}
	}
	return nil
}
