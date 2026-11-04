# Phase 2: persistent base-chain reconciliation and adversarial packet lab

## Policy lifecycle

`RenderDenyBaseline(guest)` produces a first-install bootstrap batch containing `add table`, `delete table` and base-chain definitions with guest INPUT and bidirectional FORWARD drops. **The guest interface must be administratively closed and isolated while bootstrapping.** Replacing hooked base chains may admit a few packets at the generation boundary; an adversarial review reproduced leakage during repeated whole-table replacement.

`RenderReconcileDeny(guest)` produces a distinct one-batch, **in-place** update: `flush chain` for the existing `guest_input` and `guest_forward`, then the three labelled guest-drop rules. It **never deletes or recreates base chains**, and fails if either chain is missing. There is no automatic fallback to full-table replacement. The CLI `-reconcile` selects the in-place renderer. No code in this repository installs either policy on a real gateway.

This in-place updater is **deny-only**; it is not yet a general grant-preserving controller. A future grant-aware reconciliation must preserve required kernel timeout bounds and not recreate hooks or accidentally restore expired authority. A remaining table containing unused stale sets does not automatically allow traffic, but set ownership/cleanup needs a designed controller.

## Test-only authorization

A separate Go build tag `netnslab` creates `portcullis_lab` and an IPv4 timeout allow-set keyed only by source IP. This intentionally **does not establish trusted client identity** and cannot be used in production.

Fixture return traffic is constrained to: uplink ingress, guest egress interface, a currently granted destination IP, **conntrack direction reply**, and `established,related` state. It is not sufficient against client-address reuse without conntrack cleanup, which remains an explicit production requirement.

## Validation

The disposable four-network-namespace CI lab verifies:

- Pre-policy reachability; IPv4/IPv6 guest INPUT, outbound and inbound FORWARD denial with separate labelled counters
- One-way UDP probes and deliberate wrong-interface mutations that expose bypasses even when ICMP replies are denied
- In-place reconciliation only after bootstrap, stable base-chain objects, and repeated deny-only updates
- Bounded high-rate UDP emission during repeated in-place reconciliation, asserting no observed packet delivery
- Whole-table first-install behavior, stale-permit cleanup, and kernel-side rollback failure
- Test authorization, timeout, TCP revocation and same-socket recovery
- Established UDP inbound return traffic blocked after explicit revocation or kernel expiry, then allowed on the same UDP socket after a fresh test grant

A passing UDP flood is useful evidence, **not a proof that every possible in-flight packet and network acceleration path is safe**. These are disposable namespace results, not live network results.

## Remaining safety gates before deployment

1. Persist and own the deny rules through boot and system firewall reload; bring guest interfaces up only after verifying the guard. Refuse networking when rules or attachments are missing.
2. Verify interface parent, VLAN, bridge, host OUTPUT, guest-local bridging, flowtables, tc/XDP, and active third-party nftables hooks.
3. Bind authorization to independently observed client attachment and address assignment, not to browser-provided IP/MAC or a bearer lease ID.
4. Implement narrowly scoped privileged IPC and atomic, bounded grant mutation; derive kernel timeouts conservatively from a verified lease.
5. Explicitly delete affected conntrack state on revocation and reassignment. Verify stale-flow, source-reuse and simultaneous IPv4/IPv6 scenarios.
6. Add interface-scoped DNS/DHCP and captive portal only after the authorization/packet boundary is independently tested.

No change to Hephaestus, UniFi, GL.iNet, physical interfaces or production firewall is authorized or made.
