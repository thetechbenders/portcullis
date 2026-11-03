# Architecture: Phase 1

## Boundaries

- **Lease/domain layer:** makes bounded time-limited decisions with an injectable clock; never interacts with kernel packet filtering. One live lease per client label, max 1,024 records, max 128-byte client label. These are resource guards, NOT reliable network identities or rate limiting.
- **Identity binding (planned):** relates a portal authorization to network clients using independently observed attachment evidence. Neither a browser-provided IP/MAC nor mere possession of a bearer lease ID proves network identity. The lease store's `Lookup` returns an expiry and an unverified client label for future reconciliation.
- **Enforcement adapter (planned):** mutates short-lived allow-set elements through narrowly authenticated IPC, never owns or deletes the persistent baseline deny. The guest INPUT/FORWARD and IPv6 default-deny rules must be installed at boot before enabling guest interfaces/forwarding, and must survive daemon crash/restart. Never use transient owner-scoped tables as the only drop boundary.
- **Kernel expiry (planned):** set element timeouts no greater than the remaining lease duration. Check authorization for every forwarded packet before any broad `ct state established accept`; revoke existing connectivity immediately and clean affected conntrack state.
- **Portal/API (planned):** unprivileged guest-facing process; validates all requests and never receives `CAP_NET_ADMIN`. A narrowly scoped privileged enforcement service verifies every requested change.
- **Guest DNS/DHCP (planned):** binds only to dedicated guest interfaces, never wildcard host listeners.
- **Observability (planned):** privacy-aware event records; never log bearer IDs.

## Planned host topology

Guest device → isolated access point → guest-only switch VLAN → gateway guest interface → enforcement → source NAT → upstream router.

Existing untagged management must be preserved. Switch/AP configuration, active host firewall rules, complete collision checks and independent recovery access remain unverified. No deployment is approved. VLAN ID and subnet must be chosen from a full site inventory, not hard-coded from one lab.

## Security invariants

1. Default-deny for guest FORWARD and guest-to-host INPUT must exist even without the daemon; do not expose host services or AP administration.
2. No alternate guest path around enforcement. Anti-spoofing must bind valid source addresses to guest ingress, and deny all discovered private/internal/VPN networks including RFC1918, 100.64/10, link-local, and management addresses; never depend only on a single /24 block.
3. IPv6 guest service is disabled for MVP: no guest IPv6 addressing/RA/DHCPv6, and explicit guest IPv6 INPUT/FORWARD drops including link-local host access.
4. Allow only guest DHCP, controlled DNS, and the local portal preauthorization. Never intercept arbitrary HTTPS; preauthorization DNS must not provide open recursion/tunneling bypass.
5. Fail closed under process crash, missing lease, failed policy update, reboot or rollback. Kernel allow-set timeouts must bound authority independently of userspace; source authorization must be checked even on established flows.
6. AP-local bridges can bypass gateway filtering for client/client or client/AP traffic. AP management and wireless isolation require independent verification.
7. Lease IDs are bearer secrets and cannot prove client identity; neither the in-memory lease store nor its `Valid` method is a security boundary.
8. Wall-clock changes, host suspend, and persistence lose or alter monotonic-time semantics. The enforcer must derive kernel remaining-time bounds conservatively and reject stale authorization.

## Planned structure

```text
cmd/portcullisd/            # privileged enforcement controller, later
internal/lease/             # volatile decision records (implemented)
internal/identity/          # independently observed client binding, later
internal/enforce/           # kernel allow-set controller, later
internal/portal/            # unprivileged onboarding, later
internal/guestnet/          # interface-scoped DHCP/DNS, later
internal/events/            # audit trail, later
web/                        # operator UI, later
tests/netns/                # isolated Linux namespaces, later
```

Next step: design and validate identity binding and persistent fail-closed nftables rules in isolated namespaces. Never mutate host-global network state during development.
