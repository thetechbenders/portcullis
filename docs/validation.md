# Validation evidence and limitations

## Current hosted test contract

- Go tests, race detector, vet, tagged lab vet and formatting.
- Disposable Linux namespaces: guest, gateway, WAN and protected LAN with virtual Ethernet only.
- nftables syntax/load and explicit **rule-labelled** guest INPUT/FORWARD counters.
- One-way UDP probes and intentional wrong-interface mutations for both FORWARD directions.
- Bootstrap validation with interface closed in the lab, followed by repeated **in-place**, same-hook-chain deny reconciliation.
- Bounded UDP flood during hundreds of in-place reconciliations. Zero observed deliveries is an empirical condition, not a formal no-gap guarantee.
- Parser and kernel-side transaction failure distinction; kernel EEXIST failure should preserve existing deny.
- Test-only IPv4 grants expire in kernel; TCP and UDP receive-path checks prove forward/reverse packet denial following revocation/expiry with positive recovery controls.

## Still unverified or excluded

Production installation, reboot/reload persistence, crash recovery, physical network interface identity, bridge/flowtable/tc/XDP paths, local host OUTPUT, AP isolation, trusted client identity, accurate lease-to-kernel mapping, real conntrack cleanup, privileged IPC, captive portal and DHCP/DNS are not implemented.

Bootstrap whole-table replacement **does** admit a narrow possible kernel packet gap and must never be treated as an online reconciler. In-place replacement holds the base chains, but its limited flood test does not certify every kernel implementation or path. No live network has been tested.
