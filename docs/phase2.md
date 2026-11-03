# Phase 2: guest ingress deny and disposable packet testing

## Demonstrated properties

`RenderDenyBaseline` emits a Go-generated nftables `inet` table fragment that drops packets entering through the named guest interface on INPUT and FORWARD, including IPv4/IPv6 and established flows. It accepts non-guest ingress and is **not a complete bidirectional isolation policy**.

The unsafe timed source-IP allow-set fixture is compiled only with Go build tag `netnslab` in the isolated lab command; it uses its own `portcullis_lab` table. Normal policy builds cannot request fixture grants.

On an ephemeral GitHub-hosted Linux runner, the namespace tests establish routing positive controls, then check that guest INPUT and FORWARD denial increments the expected nftables drop counters. The guest's IPv6 gateway neighbor entry is pinned to avoid neighbor discovery being mistaken for a FORWARD drop. The TCP test requires an initially working socket, a firewall drop counter increment and a receive timeout after removing a test element while the server stays alive and receives no second payload, then a successful ACK **on the same socket** after restoring the grant. A short kernel set timeout also removes guest IPv4 forwarding independently of any userspace service.

These observations are evidence about this disposable topology only. They do **not** establish production anti-spoofing, conntrack cleanup, IPv6 routing in an arbitrary host firewall, or isolation of traffic headed *towards* guests.

## Remaining security gates

1. **Policy convergence and atomicity:** nftables table declarations are not idempotent replacement operations. Reapplying rendered text to an existing table may append rules and retain old permits. The lab switches between different tables with a single nftables transaction, but the production installer must own a safe, atomic, idempotent ruleset update strategy. Never use bare `nft -f` on a live existing table on the assumption it replaces policy.
2. **Bidirectional filtering:** the current rules match `iifname guest`, not `oifname guest`. WAN or LAN hosts might still send packets *toward* a guest even though replies cannot pass. Design reverse-direction rules and independently test UDP, established TCP, link-local, and other host interface addresses.
3. **Interface and hook ownership:** a misnamed/renamed guest interface, bridge, VLAN error, flowtable offload, tc/XDP, or conflicting host firewall can bypass this narrow hook. The installer must validate real interface identity/parent, bridge topology and all active packet paths before enabling the guest interface.
4. **Persistent deny:** the existing host ruleset may be flushed on firewall reload, removing this table. A single boot/reload policy owner must establish and verify the deny *before* guest networking and forwarding become active, including on crash, reload and rollback.
5. **Trusted client binding:** source IP in the lab is spoofable; real permits must bind to independently observed attachment and address assignment. The portal must remain unprivileged, with narrow authenticated IPC to the enforcer and strict validation.
6. **Expiry and revocation:** kernel allow-set timeouts must not outlive the lease's remaining lifetime; delete matching conntrack state as well as rule elements; test TCP/UDP flows in both directions under expiration and explicit revocation.
7. **AP-local networks:** bridge/client isolation and AP-management restrictions cannot be guaranteed by routed nftables INPUT/FORWARD drops.

## Deployment prohibition

No production installer, persistent ruleset ownership, identity observation, privileged controller, DHCP/DNS or portal exists. No Hephaestus, UniFi or GL.iNet settings have been changed. Never run the privileged namespace script on a host that is not disposable.
