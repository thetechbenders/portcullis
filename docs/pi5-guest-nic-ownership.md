# Raspberry Pi 5 guest NIC ownership: hardware gate and controlled-test plan

**Status: proposed, non-executable review contract, subordinate to [ADR-001](adr/0001-pi5-physical-interface-ownership.md), which remains proposed and not accepted.** Where requirements differ, the stricter safety requirement controls pending explicit resolution. This document neither authorizes nor performs interface, NetworkManager, nftables, routing, sysctl, package, or service changes. Never run the disposable namespace launcher on physical NICs.

## Evidence and boundary

The November 5, 2026 physical reconnaissance observed a separate USB Realtek `0bda:8156` 2.5GbE NIC (`r8152` v1.12.13), enumerating at 480 Mb/s USB speed. Its current and permanent MACs matched. The three *candidate* roles are:

| Role | Interface | Evidence | Unresolved |
| --- | --- | --- | --- |
| Management | `wlan0` | Connected; holds SSH address and return route | Independent console/recovery path and uninterrupted management acceptance |
| Uplink | `eth0` | No carrier/address/route in the earlier inventory | Physical isolated peer, cabling, addressing and ownership |
| Guest | USB Realtek NIC | Separate physical parent; no carrier, addresses, routes, master or upper devices | Administrative DOWN, IPv6 policy, NetworkManager exclusivity and independent link isolation |

The **private** pinned plan parsed, but `portcullis-host check -plan` returned **1**, with `guest_exposed` (interface administratively UP) and `guest_ipv6_enabled`. The guest NIC was NetworkManager-managed with autoconnect enabled; the full manager configuration could not be independently inspected without privilege. No cable carrier does **not** establish fail-closed isolation. Forwarding controls were observed disabled but are point-in-time evidence, not a security guarantee.

Do not commit MACs, addresses, boot IDs, private plan contents or sysfs identifiers. A plan digest can enable offline guesses about redacted identities. Retain raw evidence in a restrictive local directory, not Git.

## Required invariants before cabling or activation

1. **Management preserved:** `wlan0` remains operator-owned and outside guest/uplink managers, bridges and rules; verify SSH ingress *and return route* before and after each authorized future step. Provide independent local access/power recovery; an SSH session alone is not rollback.
2. **Immutable physical role binding:** independently verify interface name, canonical physical-parent sysfs path, current/permanent MAC, USB VID:PID and driver; prohibit role swaps on hotplug/renaming. Missing/changed identity is a hard stop.
3. **Manager exclusivity:** a narrowly scoped, persistent NetworkManager exclusion must target **only** the verified guest NIC. Treat this exclusion as fallible: a missed match (port/parent change, interface rename, driver rebind, typo) must independently leave the guest DOWN and unable to exchange packets, not fail open into NetworkManager's default Ethernet autoconnect. Test both accurate and missed matches after hotplug, restart and reboot; exclude alternative owners such as systemd-networkd, dhcpcd, ifupdown, netplan/cloud-init and related address-discovery helpers. Do not broadly disable Ethernet management or modify `wlan0`.
4. **Guest starts DOWN:** the guest remains administratively DOWN until guard installation, bypass/topology attestation, correct addressing and independent isolation requirements are satisfied. Every newly enumerated netdev instance must independently have administrative DOWN, guest-only IPv6/RA restrictions and manager exclusion established **before any UP**; USB replug, rebind or reboot resets kernel per-interface defaults. A matcher miss must not allow exposure. No service may raise it merely because the cable appears or NetworkManager reconnects. A disconnected cable is not a software interlock.
5. **IPv6 is intentional:** either deny all guest IPv6 with independently verified INPUT/FORWARD/OUTPUT behavior or explicitly isolate and attest any supported IPv6 design. For an IPv6-disabled guest, set and read back per-guest-interface `disable_ipv6=1` and `accept_ra=0` before exposure, after each re-enumeration; never change host-wide `all.*` or `default.*` forwarding/IPv6/RA knobs without a separate impact review and management canary. NetworkManager may process RA in userspace even when kernel `accept_ra=0`; this alone is not proof of RA isolation. Assess DHCPv6, IPv6 link-local/NDP/DAD/MLD and IPv4 link-local or Avahi traffic. Do not rely on disabling a single sysctl as the sole enforcement layer.
6. **Guard continuity:** restore and attest the guard on every cold boot, before any possible guest UP; never run full-table bootstrap/replacement on an exposed guest link. Existing hooked base chains must persist across reconciliation; review `nftables.service` and any `flush ruleset` behavior as an explicit destructive-guard hazard. The current guest-specific `iifname` rules under `policy accept` can miss a renamed/unknown guest NIC: require revised default-deny guard schema or independently proven rename impossibility **before** physical exposure. Unknown NIC INPUT and host OUTPUT also need independent deny evidence. For graceful stop, isolate guest and verify readback **before** stopping services. Fail to guest-link isolation when guard health or attestation is uncertain. Verify tc/XDP/offload and other bypass paths, not only an nftables table dump.
7. **Failure means no unauthorized exposure:** cover controller crash/SIGKILL, supervisor restart, power loss/reboot, failed or partial manager configuration, NetworkManager matcher miss/restart, USB unplug/replug and driver rebind, guard flush or `nftables.service` reload, unexpected interface UP, stale source state and absent conntrack. Grants already installed in the kernel may remain effective until their bounded expiry (at most 15 minutes) after a controller crash unless a **tested** finalizer isolates the guest. Never claim immediate revocation or isolation without positive read-back; explicitly report `isolation_unconfirmed` when evidence is missing.
8. **No LAN leakage:** block physical activation until wildcard host listeners, unknown-NIC INPUT, host-originated OUTPUT (including IPv6 NDP/MLD and IPv4 mDNS/LLMNR), route policy/rules and routing to management/protected networks have been examined and verified under negative packet tests. `check -plan` does not attest all of these.
9. **Private evidence:** preflight and privileged checks must not disclose raw identities, NetworkManager keyfiles, Wi-Fi PSKs, SSH material or other secrets into issues, CI logs or shared reports. Bind future approvals to boot ID, plan and guard-attestation digests and a bounded expiry without publishing the identifiers.

## Proposed sequence: separate approvals, not an executable checklist

### Gate A: passive evidence (authorized by read-only reconnaissance)

- Confirm the USB NIC is still cable-disconnected, with no carrier, addresses, routes or bridge membership.
- Capture the live private inventory and run `check -plan` with the private pinned plan. Record all `hazards[]`, `not_assessed[]`, kernel version and NetworkManager evidence.
- Record whether the guest is still UP/IPv6-enabled. **Do not change either condition in Gate A.**
- Confirm physical identity and the management return route, and establish the intended isolated peer and non-overlapping address ranges.

**Gate A pass** means evidence is sufficient to *propose* an implementation; it never means guest activation is permitted.

### Gate B: separately reviewed and authorized host-owner transaction

**Require a confirmed-disconnected guest cable for the entire initial transaction, every state-changing step and rollback.** Establish a local-console recovery method or independently proven automatic dead-man revert before any host write. An intermediate loss of management must trigger rollback, not merely appear in a report. Verify any NetworkManager reload cannot bounce `wlan0`.

Before writing a host configuration implementation, produce an exact diff and rollback for a guest-only NetworkManager exclusion; prove interface identity matching does not catch `wlan0` or `eth0`. Independently specify:

- What component owns the guest link at boot, hotplug, normal shutdown and fault.
- How guest administrative DOWN is enforced prior to and independently of the Portcullis daemon.
- How IPv6 is blocked or controlled without relying only on a single sysctl.
- A real supervisor ordering/dependency graph, with guard installation and attestation preceding link activation.
- Read-back assertions after **every** state-changing step and an emergency physical disconnect mechanism.
- A rollback sequence available from an independent console even if SSH or NetworkManager fails, with automatic timed revert or local-console-only application; verify management interface connections, routes and sysctls are unchanged.
- Explicit per-new-netdev DOWN, IPv6 disablement and RA restriction before any UP, even when a guest-only NetworkManager matcher fails or the driver changes; verify readback after each operation.
- NetworkManager exclusion and other interface-manager precedence, independently of the USB name, port and `r8152` driver remaining stable.

A separate, explicitly approved **privileged read-only audit** must precede Gate B mutations: inspect root-readable NetworkManager profiles and competing managers without exporting connection secrets or Wi-Fi PSKs. A privileged change must have its own explicit operator approval. Avoid speculative systemd/NetworkManager snippets until that audit establishes ownership. No unattended first application to the physical Pi.

### Gate C: disposable compatibility and failure tests

Before hardware packet testing, use only disposable runners to validate nftables 1.1.3 semantics, conntrack dependency, cold-boot guard restoration, guard continuity, IPv4/IPv6 INPUT/FORWARD/OUTPUT, hotplug/reboot assumptions and fault-injection behavior. Inject a missed NetworkManager matcher, USB replug/name change/driver rebind, manager restart, guard removal, nftables reload, supervisor restart and SIGKILL. Test both a proper guard and deliberately missing/modified rules, including the `policy accept`/`iifname` rename hole. Each denied probe requires a positive control and observed counters: guest to management subnet, guest to host wildcard listeners (including SSH), IPv6 link-local to host, guest to uplink peer before grant, unsolicited uplink to guest, and host-originated OUTPUT toward the guest. Assert byte-identical management connections, routes and sysctls before/after. **Disposable CI cannot certify Pi kernel/r8152 behavior:** require a separately authorized privileged *read-only* Pi attestation before Gate D. Treat failures or unknown bypass paths as blockers.

### Gate D: supervised isolated physical acceptance (future, separately approved)

With a confirmed local recovery path and two independently verified, isolated peers, start with guest cable disconnected. Verify the guest is DOWN, guards are installed and attested, and only then explicitly allow a controlled wired guest connection. Exercise DHCP, captive portal, deny-before-grant, scoped temporary grants, expiry, revocation, crash/restart, USB replug, NetworkManager restart, physical disconnect and recovery. Cold boot with cable connected is forbidden in the first pilot; unattended connected-boot acceptance is a separate later gate. Capture actual packet evidence and guard counters, not just process health. Restore the guest to DOWN and verify absence of unauthorized routes/addresses as a final acceptance step.

## Current stop conditions

- `guest_exposed` or `guest_ipv6_enabled` remains unresolved.
- NetworkManager autoconnect/ownership has not been reviewed and constrained, or a missed guest matcher can cause device UP/configuration.
- `eth0` peer/cabling and dedicated guest test device have not been independently verified.
- `conntrack` binary is missing and actual kernel/privileged compatibility is untested.
- Independent out-of-band recovery, supervisor and cold-boot policy, and packet/fault evidence are absent.
- Guard still relies on `policy accept` plus guest `iifname` binding without a verified unknown/renamed-NIC deny (ADR-001 guard-schema issue); or host OUTPUT/INPUT leaks remain unresolved.
- An inventory exit 0 or `check -plan` exit 0 is never activation authorization.

## Scope of this PR

This PR records the observed physical hazard and defines testable, staged approval gates. It intentionally makes **no** network configuration or code changes. The next implementation PR should tackle guest-only ownership and fail-closed link lifecycle in isolation, backed by a disposable test harness. Reference: [ADR-001 (proposed, not accepted)](adr/0001-pi5-physical-interface-ownership.md), [host preflight](host-preflight.md), [Formnext design contract](formnext-design.md), [repository status](../README.md).
