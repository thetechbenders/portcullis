# Phase 3: guard attestation before any privileged enforcement

Phase 3 introduced a deliberately **pure read-only verifier**. It consumes the JSON output of `nft -j list table inet portcullis_guard` but never executes `nft`, changes network state, or installs firewall rules.

## Deny-only attestation contract

`enforce.VerifyDenyGuardJSON(data, guest)` returns an error for missing or oversized state, malformed JSON, a dormant table, missing/wrong hooks, unexpected priorities, missing or extra chains and rules, incorrect guest interface names, and anything other than the exact three deny rules and their counters in the owned table.

The intended chain topology is guest INPUT at priority -50, guest FORWARD at priority -50, both type filter and policy accept, with labelled drops for guest INPUT and both guest FORWARD directions.

This is only a **snapshot validator for the known Phase 2 deny-only policy**. It does not attest to kernel execution paths, real physical interface identity, flowtables, bridge forwarding, host OUTPUT, tc/XDP, host firewalls, races between verification and use, or genuine client identity. A future privileged owner must prove those separately and must never continue if attestation fails.

**Historical scope:** this file describes the initial deny-only Phase 3 attestor, not the entire current repository. The later Formnext vertical slice includes a privileged controller exercised in disposable network namespaces; see [Formnext integration evidence](formnext-integration.md) and [the demo contract](formnext-design.md). Those tests do not establish physical Pi readiness. Persistent boot and host-manager ownership, reload and rename bypass handling, recovery, privileged physical activation, and real packet-path acceptance remain separate unverified requirements. No live-host modification is authorized by this document.

## Security-negative tests

Unit tests deliberately mutate dormant status, chain hook/priority/policy, missing chains/rules, wrong interface, accept verdict, extra owned objects, and malformed JSON. They must all be rejected.
