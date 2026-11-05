package enforce

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fixtureListing() map[string]any {
	match := func(dir string) map[string]any {
		return map[string]any{"match": map[string]any{
			"op": "==", "left": map[string]any{"meta": map[string]any{"key": dir}}, "right": "guest0",
		}}
	}
	rule := func(chain, label, dir string) map[string]any {
		return map[string]any{"rule": map[string]any{
			"family": "inet", "table": guardTable, "chain": chain, "comment": label,
			"expr": []any{match(dir), map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"drop": nil}},
		}}
	}
	chain := func(name, hook string) map[string]any {
		return map[string]any{"chain": map[string]any{
			"family": "inet", "table": guardTable, "name": name, "type": "filter",
			"hook": hook, "prio": -50, "policy": "accept",
		}}
	}
	return map[string]any{"nftables": []any{
		map[string]any{"metainfo": map[string]any{"version": "1.0.9"}},
		map[string]any{"table": map[string]any{"family": "inet", "name": guardTable}},
		chain("guest_input", "input"), chain("guest_forward", "forward"),
		rule("guest_input", "guest-input", "iifname"),
		rule("guest_forward", "guest-egress", "iifname"),
		rule("guest_forward", "guest-ingress", "oifname"),
	}}
}

func TestVerifyDenyGuardJSON(t *testing.T) {
	good := fixtureListing()
	raw, _ := json.Marshal(good)
	if err := VerifyDenyGuardJSON(raw, "guest0"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDenyGuardJSON(raw, "bad;guest"); !errors.Is(err, ErrGuestInterface) {
		t.Fatalf("expected invalid interface: %v", err)
	}
}

func TestVerifyDenyGuardRejectsMutations(t *testing.T) {
	tests := map[string]func([]any) []any{
		"dormant": func(x []any) []any {
			x[1].(map[string]any)["table"].(map[string]any)["flags"] = []any{"dormant"}
			return x
		},
		"unhooked":       func(x []any) []any { delete(x[2].(map[string]any)["chain"].(map[string]any), "hook"); return x },
		"wrong hook":     func(x []any) []any { x[3].(map[string]any)["chain"].(map[string]any)["hook"] = "output"; return x },
		"wrong priority": func(x []any) []any { x[3].(map[string]any)["chain"].(map[string]any)["prio"] = 0; return x },
		"wrong policy":   func(x []any) []any { x[2].(map[string]any)["chain"].(map[string]any)["policy"] = "drop"; return x },
		"missing chain":  func(x []any) []any { return append(x[:3], x[4:]...) },
		"missing rule":   func(x []any) []any { return x[:len(x)-1] },
		"extra rule":     func(x []any) []any { return append(x, x[5]) },
		"wrong interface": func(x []any) []any {
			r := x[5].(map[string]any)["rule"].(map[string]any)
			r["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "wrongif0"
			return x
		},
		"allow instead of drop": func(x []any) []any {
			r := x[6].(map[string]any)["rule"].(map[string]any)
			r["expr"].([]any)[2] = map[string]any{"accept": nil}
			return x
		},
		"extra chain": func(x []any) []any {
			return append(x, map[string]any{"chain": map[string]any{"family": "inet", "table": guardTable, "name": "other"}})
		},
		"unexpected set": func(x []any) []any {
			return append(x, map[string]any{"set": map[string]any{"family": "inet", "table": guardTable, "name": "grant"}})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := fixtureListing()
			f["nftables"] = mutate(f["nftables"].([]any))
			raw, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyDenyGuardJSON(raw, "guest0"); !errors.Is(err, ErrGuardAttestation) {
				t.Fatalf("unsafe nft state accepted: %v", err)
			}
		})
	}
}

func TestVerifyDenyGuardRejectsMalformed(t *testing.T) {
	for _, input := range []string{"", "{}", "[]", "{", `{"nftables":[]}`, `{"nftables":[{"table":{"family":"inet","name":"portcullis_guard","flags":["dormant"]}}]}`} {
		if err := VerifyDenyGuardJSON([]byte(input), "guest0"); !errors.Is(err, ErrGuardAttestation) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestDenyAttestationRejectsAmbiguousAndMalformedFields(t *testing.T) {
	good, err := json.Marshal(fixtureListing())
	if err != nil {
		t.Fatal(err)
	}
	replace := func(old, new string) string {
		t.Helper()
		s := string(good)
		if !strings.Contains(s, old) {
			t.Fatalf("fixture missing %q", old)
		}
		return strings.Replace(s, old, new, 1)
	}
	cases := map[string]string{
		"duplicate root":         replace(`"nftables":`, `"nftables":[],"nftables":`),
		"duplicate object kind":  replace(`"table":{`, `"table":{},"table":{`),
		"duplicate rule comment": replace(`"comment":"guest-egress"`, `"comment":"bogus","comment":"guest-egress"`),
		"duplicate nested match": replace(`"op":"=="`, `"op":"!=","op":"=="`),
		"top-level extra":        strings.TrimSuffix(string(good), "}") + `,"other":42}`,
		"empty metainfo":         replace(`"metainfo":{"version":"1.0.9"}`, `"metainfo":null`),
		"null table flags":       replace(`"name":"portcullis_guard"}`, `"name":"portcullis_guard","flags":null}`),
		"unknown table field":    replace(`"name":"portcullis_guard"}`, `"name":"portcullis_guard","flags_extra":["dormant"]}`),
		"missing chain family":   replace(`"chain":{"family":"inet",`, `"chain":{`),
		"counter fractional":     replace(`"packets":0`, `"packets":0.5`),
		"counter negative":       replace(`"bytes":0`, `"bytes":-1`),
		"verdict payload":        replace(`"drop":null`, `"drop":{"unexpected":true}`),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyDenyGuardJSON([]byte(input), "guest0"); !errors.Is(err, ErrGuardAttestation) {
				t.Fatalf("malformed deny guard accepted: %v", err)
			}
		})
	}
}
