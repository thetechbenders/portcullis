# Validation contract

## Available now

`go test ./...` exercises lease issuance, unknown/empty IDs, invalid durations, exact-boundary expiry, revocation, restart fail-closed behavior, and pruning. `go test -race ./...` checks for data races. `go vet ./...` checks static issues.

## Required before any real guest network

- Run Linux network-namespace integration tests that simulate a guest, uplink, portal, and firewall; do not touch production networking.
- Verify guest DNS/DHCP are interface-scoped and trusted-LAN services remain reachable only from the management side.
- Demonstrate denial before authorization, grant after validated identity, and complete revocation of **existing TCP/UDP flows** at expiry/logout/crash.
- Test spoofed MAC/IP, alternative DNS, static routes, IPv6, captive-portal detection, and controlled preauth DNS.
- Verify no guest access to SSH, editor, terminal handoff, UniFi management, Slate management or private/VPN routes.
- Test firewall transaction failure, restart, clock jumps, stale grants, and policy convergence.
- Test switch and AP client isolation separately from host enforcement.
- Inspect live nftables rules before integration and confirm console/controller recovery, backups, rollback and port-profile preservation.

No hardware or production gateway tests have been run.
