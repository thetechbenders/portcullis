# Validation contract

## Current evidence

The Go unit suite covers lease issuance, IDs, input limits, duplicate active client labels, maximum store capacity, expiry boundaries, lookup, revocation, volatile-store semantics and pruning. A concurrent issue/validate/prune/revoke test runs under `go test -race ./...`; `go vet ./...` and repo-wide `gofmt` run in CI.

The separate, privileged **GitHub-hosted disposable netns** CI job compiles the policy renderer and creates guest, gateway, upstream, and protected-LAN namespaces. It checks nft syntax and verifies packet paths before and after a deny policy, IPv4 and IPv6 guest denial, IPv4 fixture grants, protected-LAN isolation, kernel set timeouts, and blockage of an established TCP exchange on grant deletion. This is not production client authorization; the timed test rule trusts a source address.

See [tests/netns/README.md](../tests/netns/README.md).

## Outstanding deployment gates

- Verify persistent default-deny INPUT/FORWARD across kernel/firewall startup, daemon crash/restart, reboots and transaction failure.
- Verify independently observed network identities, source/attachment binding, DHCP reassignment, MAC/IP spoofing and concurrent client sessions.
- Verify revocation and expiration of **established TCP/UDP** flows and actual conntrack cleanup. An application ACK being blocked alone does not prove conntrack deletion.
- Validate DHCP/DNS and preauthorization services are interface-scoped and do not allow bypasses (alternate DNS, DoT, IPv6, captive detection, static routes).
- Verify no guest path to SSH, protected host services, switch/AP management, LAN/VPN/internal networks or other guest devices.
- Validate controller privilege separation, narrow IPC contracts and atomic allow-set updates.
- Test failure injection, suspended monotonic clock, stale grants, persistent state reconciliation and rollback handling.
- Inspect production nftables state, validate physical switch/AP isolation, and establish independent recovery and rollback before live integration.

No hardware or production gateway tests have been run.
