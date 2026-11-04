# Phase 2: atomic guest isolation policy and disposable packet tests

## What is implemented

`RenderDenyBaseline` emits one nftables `inet` batch that defines the owned `portcullis_guard` table, with guest INPUT denied and guest FORWARD denied for **both** `iifname` and `oifname`. This covers IPv4 and IPv6 packet paths in the namespace lab. Default policies are `accept` for unrelated ingress, so this is a **guest-specific isolated path**, not a general host firewall.

The batch uses `add table`, `delete table`, then a new declaration, all in a **single** `nft -f` transaction. It works whether the owned table was initially absent or present, avoids accumulated duplicate rules or sets, removes deliberately injected stale permits, and reliably removes stale rules in the settled state. **This is not packet-gap-free:** independent stress testing observed three leaked UDP packets during approximately 14,300 base-chain replacements. Therefore the entire-table replacement method is prohibited for live reconciliation. A kernel-side EEXIST error rolls back the batch; a parser error alone would not establish that property. The generator itself never invokes nft.

The unsafe timed source-IP test grant remains isolated behind Go's `netnslab` build tag in a separate binary and `portcullis_lab` table. It is **not an authentication mechanism**. The lab fixture additionally checks conntrack's reply direction for return packets, but has not yet demonstrated that inbound packets are denied immediately after grant revocation/expiry in the presence of existing tracked flows.

## Verified in disposable GitHub Actions

- Prior CI validated IPv4/IPv6 denial with chain-aggregate counters, which were susceptible to reverse-path false passes. The current branch adds per-rule labelled counters and one-way IPv4 UDP mutation probes; these stronger tests require fresh exact-head CI before they are counted as verified.
- Positive connectivity controls before installing policy, including reverse WAN/LAN-to-guest paths.
- One-shot atomic policy reapplication on an existing table, no duplicate FORWARD rules, and deletion of injected stale broad permits.
- The earlier parser-error test did not test kernel rollback. The current branch uses a kernel-side duplicate-table operation for a stronger rollback regression, pending fresh CI.
- Test-only temporary source-IP authorization and kernel expiry without a userspace daemon.
- An already-open TCP exchange is blocked after revocation, with server liveness, drop counters, and subsequent same-socket recovery after test regrant.

These results are limited to the disposable namespace topology. They do **not** establish complete production packet-path control.

## Remaining deployment gates

1. **Reconciliation safety:** never recreate hooked base chains on a live path. Design persistent base chains with an in-place atomic rule/update policy; preserve timed grants explicitly and test high-rate packet flooding for bypasses before production.\n2. **Ruleset ownership and persistence:** A third-party `flush ruleset`, system service reload, boot ordering, or netplan interface rename can remove or bypass the guard. The deployment controller must verify ownership, interface attachment/parent, and hook topology before enabling guest traffic. Do not treat the renderer as a production installer.
2. **Other paths:** OUTPUT from the local host to guests, bridged forwarding, flowtables/offload, tc/XDP redirection, and AP-local traffic are not covered by this simple `inet` INPUT/FORWARD fixture. Separate policy and testing are required.
3. **Reliable identity:** Source-IP-only grants are spoofable. The eventual controller must independently attest attachment and address binding, and enforce strict privileged IPC.
4. **Kernel lifetime and cleanup:** Derive permit timeouts conservatively from current lease authority, revoke live traffic atomically, and delete affected conntrack state. The current TCP evidence does not prove conntrack cleanup.
5. **Real integration:** DHCP/DNS preauthorization, captive portal, VLAN switch profile, AP management separation, crash/reboot recovery, and physical network safety remain unimplemented.

No Hephaestus, UniFi or Slate changes are authorized or performed.
