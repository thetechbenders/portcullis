package enforce

import "fmt"

// VerifyNoBypass attests "nft -j list ruleset" output. It rejects packet
// paths that skip the inet forward hook the guard relies on: flowtables
// (fast-path offload), any ingress/egress base chain in any family (nft
// 1.0.9 JSON does not show a netdev chain's device, so all are rejected),
// and dup/fwd statements, which emit packet copies outside the forward hook.
// A portcullis_guard table in another family, or a missing inet guard, also
// fails. The guard's own objects in this same listing must pass the exact
// guard verification, so both checks describe one consistent ruleset.
//
// Ordinary tables elsewhere are allowed: a drop in any base chain is final,
// and an accept in another table cannot override this guard's drop.
func VerifyNoBypass(ruleset []byte, c GuardConfig) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrGuardAttestation, err)
	}
	objs, err := decodeListing(ruleset, maxRulesetJSONBytes)
	if err != nil {
		return err
	}
	var guard []nftObject
	for _, o := range objs {
		family, ok := o.body["family"].(string)
		if !ok || family == "" {
			return attestErr("object without family")
		}
		owner, key := "table", "table"
		if o.kind == "table" {
			key = "name"
		}
		name, ok := o.body[key].(string)
		if !ok {
			return attestErr("object without %s", owner)
		}
		if name == GuardTable {
			if family != "inet" {
				return attestErr("%s table in family %.16q", GuardTable, family)
			}
			guard = append(guard, o)
			continue
		}
		switch o.kind {
		case "flowtable":
			return attestErr("flowtable present")
		case "chain":
			if hook, present := o.body["hook"]; present {
				h, ok := hook.(string)
				if !ok || h == "ingress" || h == "egress" {
					return attestErr("ingress/egress base chain present")
				}
			}
		case "rule":
			if containsKey(o.body["expr"], "dup", "fwd") {
				return attestErr("dup/fwd statement present")
			}
		}
	}
	hasTable := false
	for _, o := range guard {
		hasTable = hasTable || o.kind == "table"
	}
	if !hasTable {
		return attestErr("inet %s table absent", GuardTable)
	}
	_, err = verifyGuardObjects(guard, c)
	return err
}

func containsKey(v any, keys ...string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, w := range x {
			for _, want := range keys {
				if k == want {
					return true
				}
			}
			if containsKey(w, keys...) {
				return true
			}
		}
	case []any:
		for _, w := range x {
			if containsKey(w, keys...) {
				return true
			}
		}
	}
	return false
}
