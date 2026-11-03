# Validation contract

## Available evidence

`go test ./...`, `go test -race ./...`, `go vet ./...` and repository-wide `gofmt` cover bounded lease records and the inert policy renderer. The build-tagged `netnslab` fixture has separate Go checks and cannot be invoked by the normal policy CLI.

The GitHub-hosted disposable netns CI job checks nftables syntax, basic packet routing preconditions, and guest IPv4/IPv6 INPUT and FORWARD drops with direction-specific nftables counter deltas. Static IPv6 gateway neighbor mapping avoids neighbor-discovery-only false positives. The test-only source-IP set demonstrates kernel expiry and, for one existing TCP connection, loss of an exchange after revocation with later recovery on the same socket.

These are **direction-limited lab observations**, not a verified production firewall. A socket being blocked does not prove the conntrack entry was deleted. The fixture source-IP allow-set is deliberately not a trusted client-authentication mechanism.

## Required for any real deployment

- Bidirectional guest isolation and separate proof of other-host-IP and IPv6 link-local blocking.
- Safe atomic, idempotent policy updates; no stale permits when policies are replaced, no fail-open gap on reload, crash, shutdown or reboot.
- Verify actual interface identity/parent, VLAN/bridge arrangements, physical switch/AP isolation and all other active nftables, bridge, flowtable, tc and XDP paths.
- Reliable authenticated client attachment identity, anti-spoofing, address reassignment and DHCP binding.
- Bounded kernel allow-set expiry derived from lease duration, true conntrack cleanup, UDP and reverse-direction flow revocation.
- Least-privilege controller and authenticated narrowly scoped IPC from the portal.
- Failure-injection tests of boot, reload, external ruleset flush, watchdog response and rollback, before connecting actual guest traffic.
- No changes to real gateway/network equipment without independent recovery, rollback and explicit deployment authorization.
