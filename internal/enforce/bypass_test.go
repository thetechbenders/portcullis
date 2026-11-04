package enforce

import (
	"encoding/json"
	"errors"
	"testing"
)

// rulesetWith builds a synthetic "nft -j list ruleset" from the real guard
// capture plus extra objects, shaped like the nft 1.0.9 testdata.
func rulesetWith(t *testing.T, extra ...any) []byte {
	t.Helper()
	doc, list := mutable(t)
	doc["nftables"] = append(list, extra...)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func obj(kind string, fields map[string]any) any { return map[string]any{kind: fields} }

func TestVerifyNoBypass(t *testing.T) {
	c := labGuard(t)
	otherTable := obj("table", map[string]any{"family": "inet", "name": "other", "handle": jnum(2)})
	otherChain := obj("chain", map[string]any{"family": "inet", "table": "other", "name": "fw", "handle": jnum(1),
		"type": "filter", "hook": "forward", "prio": jnum(0), "policy": "accept"})
	otherRule := obj("rule", map[string]any{"family": "inet", "table": "other", "chain": "fw", "handle": jnum(2),
		"expr": []any{map[string]any{"accept": nil}}})
	if err := VerifyNoBypass(rulesetWith(t), c); err != nil {
		t.Fatalf("guard-only ruleset rejected: %v", err)
	}
	if err := VerifyNoBypass(rulesetWith(t, otherTable, otherChain, otherRule), c); err != nil {
		t.Fatalf("ordinary filter table rejected: %v", err)
	}

	doc, list := mutable(t)
	i, _ := find(list, "rule", "comment", "guest-egress")
	doc["nftables"] = append(list[:i], list[i+1:]...)
	brokenGuard, _ := json.Marshal(doc)
	noGuard, _ := json.Marshal(map[string]any{"nftables": []any{list[0], otherTable}})

	for name, data := range map[string][]byte{
		"dormant truncated": readFixture(t, "ruleset_dormant_truncated_nft-1.0.9.json"),
		"guard absent":      noGuard,
		"guard mutated":     brokenGuard,
		"flowtable": rulesetWith(t, otherTable, obj("flowtable", map[string]any{"family": "inet", "table": "other",
			"name": "ft", "handle": jnum(3), "hook": "ingress", "prio": jnum(0), "dev": "guest0"})),
		"netdev ingress": rulesetWith(t, obj("table", map[string]any{"family": "netdev", "name": "nd", "handle": jnum(3)}),
			obj("chain", map[string]any{"family": "netdev", "table": "nd", "name": "ing", "handle": jnum(1),
				"type": "filter", "hook": "ingress", "prio": jnum(0), "policy": "accept"})),
		"inet egress": rulesetWith(t, otherTable, obj("chain", map[string]any{"family": "inet", "table": "other",
			"name": "eg", "handle": jnum(1), "type": "filter", "hook": "egress", "prio": jnum(0), "policy": "accept"})),
		"guard name in ip family": rulesetWith(t, obj("table", map[string]any{"family": "ip", "name": GuardTable, "handle": jnum(5)})),
		"dup statement": rulesetWith(t, otherTable, otherChain, obj("rule", map[string]any{"family": "inet", "table": "other",
			"chain": "fw", "handle": jnum(2), "expr": []any{map[string]any{"dup": map[string]any{"addr": "198.18.0.2"}}}})),
		"trailing data": append(rulesetWith(t), []byte(" []")...),
	} {
		if err := VerifyNoBypass(data, c); !errors.Is(err, ErrGuardAttestation) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
