# Phase 3: guard attestation before any privileged enforcement

This branch begins Phase 3 with a deliberately **pure read-only verifier**. It consumes the JSON output of `nft -j list table inet portcullis_guard` but never executes `nft`, changes network state, or installs firewall rules.

## Deny-only attestation contract

`enforce.VerifyDenyGuardJSON(data, guest)` returns an error for missing or oversized state, malformed JSON, a dormant table, missing/wrong hooks, unexpected priorities, missing or extra chains and rules, incorrect guest interface names, and anything other than the exact three deny rules and their counters in the owned table.

The intended chain topology is guest INPUT at priority -50, guest FORWARD at priority -50, both type filter and policy accept, with labelled drops for guest INPUT and both guest FORWARD directions.

This is only a **snapshot validator for the known Phase 2 deny-only policy**. It does not attest to kernel execution paths, real physical interface identity, flowtables, bridge forwarding, host OUTPUT, tc/XDP, host firewalls, races between verification and use, or genuine client identity. A future privileged owner must prove those separately and must never continue if attestation fails.

No controller is implemented or authorized to modify a live host. The next step is to validate against real nft-generated JSON **inside disposable netns CI**, then design an owner/attestation lifecycle including boot ordering, reload detection, privileged IPC, and rollback.

## Security-negative tests

Unit tests deliberately mutate dormant status, chain hook/priority/policy, missing chains/rules, wrong interface, accept verdict, extra owned objects, and malformed JSON. They must all be rejected.
