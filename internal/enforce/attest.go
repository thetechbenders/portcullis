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
	var document struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&document); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrGuardAttestation, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: trailing content", ErrGuardAttestation)
	}
	if len(document.Nftables) == 0 {
		return fmt.Errorf("%w: empty nftables listing", ErrGuardAttestation)
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
	for _, raw := range document.Nftables {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil || len(entry) != 1 {
			return fmt.Errorf("%w: invalid listing element", ErrGuardAttestation)
		}
		for kind, payload := range entry {
			if kind == "metainfo" {
				continue
			}
			var o struct {
				Family  string          `json:"family"`
				Table   string          `json:"table"`
				Name    string          `json:"name"`
				Chain   string          `json:"chain"`
				Type    string          `json:"type"`
				Hook    string          `json:"hook"`
				Prio    json.RawMessage `json:"prio"`
				Policy  string          `json:"policy"`
				Flags   []string        `json:"flags"`
				Comment string          `json:"comment"`
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
						"op": "==",
						"left": map[string]any{"meta": map[string]any{"key": exp.key}},
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
				if _, ok := counter["packets"].(float64); !ok {
					return fmt.Errorf("%w: malformed counter %q", ErrGuardAttestation, o.Comment)
				}
				if _, ok := counter["bytes"].(float64); !ok {
					return fmt.Errorf("%w: malformed byte counter %q", ErrGuardAttestation, o.Comment)
				}
				if _, ok := o.Expr[2]["drop"]; !ok || len(o.Expr[2]) != 1 {
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
