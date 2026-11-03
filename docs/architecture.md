# Architecture: Phase 1

## Boundaries

- **Lease/domain layer:** makes time-limited authorization decisions with an injectable clock; never interacts with kernel packet filtering.
- **Identity binding (planned):** relates a portal authorization to a network client through verified attachment evidence. An arbitrary client label, IP address, or MAC presented by a browser is **not** proof of identity.
- **Enforcement adapter (planned):** owns a narrowly scoped nftables table and atomic policy updates, and refuses access without current validated authority. Expiration and revocation must apply to established connections too.
- **Portal/API (planned):** handles onboarding and strictly validates all mutation requests. The browser is never an enforcement boundary.
- **Guest DNS/DHCP (planned):** binds to dedicated guest interfaces, never wildcard host listeners.
- **Observability (planned):** structured events with privacy-aware client IDs, denial reasons and enforcement health.

## Planned host topology

Guest device → dedicated Slate AP → guest-only UniFi VLAN → Hephaestus guest VLAN interface → authorization enforcement → source NAT → existing home router.

The host's existing untagged management connection must be preserved. The switch and Slate configuration, active firewall rules, full route collision checks and independent recovery access remain unverified. No deployment is approved.

Provisional values only: VLAN 3030, 10.77.30.0/24, gateway 10.77.30.1. Do not use them without checking existing UniFi, VPN and upstream route allocations.

## Security invariants

1. Default deny for guest forward AND guest-to-host INPUT; never expose SSH, management, or AP administration to guests.
2. No alternate guest route around enforcement. Block spoofed sources and restrict all internal routed prefixes, not just one home /24.
3. Guest IPv6 is denied for MVP, including host INPUT and forwarding; no RAs or delegated prefix.
4. Only explicitly needed DHCP, controlled DNS and local portal reachability are allowed before authorization. Do not intercept arbitrary HTTPS.
5. Fail closed across process crash, bad config, lost authority, restart, and rollback. Existing conntrack flows must not survive revocation.
6. A local guest AP bridge may bypass the host entirely for client-to-client or client-to-AP traffic. Verify wireless/client isolation and AP management separation independently.
7. The lease store currently has **no verified identity and no packet enforcement**. It is only a domain primitive, never a security boundary.

## Planned structure

```text
cmd/portcullisd/            # privileged controller, later
internal/lease/             # time-based domain logic (implemented)
internal/identity/          # AP/lease binding, later
internal/enforce/           # nftables owner, later
internal/portal/            # guest onboarding, later
internal/guestnet/          # DHCP/DNS integration, later
internal/events/            # audit trail, later
web/                        # operator UI, later
tests/netns/                # isolated Linux namespace e2e, later
```

Next critical path: design identity binding and nftables enforcement in isolated network namespaces. No host-global nft commands or network changes during development.
