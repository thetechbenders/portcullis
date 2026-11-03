# Validation contract

## Available now

`go test ./...` covers issuance, IDs, input limits, duplicate active client labels, maximum store capacity, expiry boundary, lookup, revocation (including expired-but-present records), volatile-store restart semantics, and pruning. Concurrent operations are exercised against the store, and `go test -race ./...` instruments those paths for data races. `go vet ./...` performs static checks. These results do NOT establish real network access control, reliable identity binding, persistence, clock-reset safety, or kernel firewall behavior.

## Required before any real guest network

- Linux namespace packet tests with guest, uplink, portal and internal network simulators, without host production network changes.
- Verify default-deny INPUT and FORWARD survive controller crash/restart and reboots; kernel timeouts must bound permitted packet flow independently.
- Verify expiry and revocation on established TCP/UDP flows, with conntrack cleanup; prohibit a broad established-flow bypass.
- Verify real network identity binding and reassignment, spoofed MAC/IP, alternate DNS, static routing, IPv6/link-local and trusted/VPN network bypasses.
- Validate interface-scoped DHCP/DNS, local portal access, limited preauth recursion, and no arbitrary HTTPS interception.
- Verify guest cannot access host services, switch/AP administration, trusted LAN or guest peers.
- Test firewall transaction failure, restart, clock jumps, suspend/resume, stale grants and reconciliation.
- Audit existing nftables rule interactions before integrating with production host; prove independent console/controller recovery, backup and rollback.

No hardware or production gateway tests have been run.
