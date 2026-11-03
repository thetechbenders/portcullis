# Validation contract

## Verified on disposable hosted Linux

Go checks include `go test ./...`, `go test -race ./...`, `go vet ./...`, formatting and separate `netnslab` build-tagged fixture tests.

The four-namespace integration lab verifies nft syntax/loading, pre-policy IPv4/IPv6 positive routing controls, and nftables drop-counter deltas for guest INPUT and **bidirectional guest FORWARD**. Both WAN and protected-LAN sources are denied from reaching the guest under the baseline. It additionally tests existing-table reapplication, removing injected broad grant rules, rejecting a malformed atomic transaction without losing deny, and restoring the exact intended rule count.

The deliberately unsafe test-only grant checks bounded IPv4 guest-to-upstream forwarding, controlled established replies, kernel expiration, TCP blocked delivery on revocation and same-socket recovery on test regrant. The server liveness and nft counters prevent treating an unrelated dead TCP server as a successful firewall revocation.

## Not established for production

- Persistent deny under real system boot, firewall reload/flush and daemon failures.
- Verified guest interface identity and parent, bridge VLAN topology, flowtable/offload/tc/XDP bypass protection.
- Host-initiated OUTPUT to a guest and AP-local traffic isolation.
- Trusted attachment identity, client anti-spoofing and address reassignment.
- Authenticated privileged controller, safe allow-set operations and real conntrack deletion.
- DHCP/DNS, captive portal preauthorization, management access and physical equipment isolation.
- UDP session/revocation tests and expiry of an established stream (distinct from new packet timeout tests).

No real network has been modified and the rendered batch is not an approved deployment mechanism.
