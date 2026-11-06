# Validation evidence and limitations

## Current hosted test contract

- Go tests, race detector, vet, tagged lab vet and formatting.
- Disposable Linux namespaces: guest, gateway, WAN and protected LAN with virtual Ethernet only.
- nftables syntax/load and explicit **rule-labelled** guest INPUT/FORWARD counters.
- One-way UDP probes and intentional wrong-interface mutations for both FORWARD directions.
- Bootstrap behavior checked in an **isolated namespace** with guest0 administratively up; these tests do not establish that bootstrap is safe on a live guest interface. Repeated **in-place**, same-hook-chain reconciliation is tested separately.
- Bounded UDP flood during hundreds of in-place reconciliations. Zero observed deliveries is an empirical condition, not a formal no-gap guarantee.
- Parser and kernel-side transaction failure distinction; kernel EEXIST failure should preserve existing deny.
- Test-only IPv4 grants expire in kernel; TCP and UDP receive-path checks exercise blocked forwarding and reply delivery after revocation/expiry, with positive recovery controls.

## Still unverified or excluded

Physical host installation and boot/reload persistence, independently verified NIC identity, NetworkManager/hotplug lifecycle, the `iifname` / base-chain `policy accept` rename bypass, bridge/flowtable/tc/XDP and host OUTPUT packet paths, access-layer station binding, management recovery and physical acceptance remain unverified. The merged Formnext disposable vertical slice does implement demo-scoped controller IPC, DHCP/DNS, portal, bounded kernel grants and conntrack cleanup, with the scope and limitations described in [integration evidence](formnext-integration.md). These have not been accepted on physical hardware.

Bootstrap whole-table replacement **does** admit a narrow possible kernel packet gap and must never be treated as an online reconciler. In-place replacement holds the base chains, but its limited flood test does not certify every kernel implementation or path. No live network has been tested.
