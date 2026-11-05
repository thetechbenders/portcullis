package enforce

import "fmt"

// VerifyNoBypass attests only nft-visible rules from "nft -j list ruleset".
// It cannot inspect iptables-legacy rules loaded through the legacy kernel
// API. Before deploying the disposable demo, verify legacy tables contain
// no non-default rules and that no other packet managers are active.
// It rejects packet
// paths that skip the inet forward hook the guard relies on: flowtables
// (fast-path offload), any ingress/egress base chain in any family (nft
// 1.0.9 JSON does not show a netdev chain's device, so all are rejected),
// and dup/fwd/queue statements or xt targets, which can emit or redirect
// packets outside the forward hook. Known xt match-only expressions are
// permitted; extension targets are not.
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
			if unsafeBypassStatement(o.body["expr"]) {
				return attestErr("packet duplication, queue, or xt target statement present")
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

// unsafeBypassStatement examines all nested nft expression values. An xt
// target can route packets outside Portcullis despite the normal nft hook.
func unsafeBypassStatement(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			switch k {
			case "dup", "fwd", "queue":
				return true
			case "xt":
				x, ok := child.(map[string]any)
				if !ok || x["type"] != "match" {
					return true
				}
			}
			if unsafeBypassStatement(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if unsafeBypassStatement(child) {
				return true
			}
		}
	}
	return false
}
