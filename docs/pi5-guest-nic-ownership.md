# Raspberry Pi 5 guest NIC ownership: hardware gate and controlled-test plan

**Status: proposed, non-executable review contract.** This document neither authorizes nor performs interface, NetworkManager, nftables, routing, sysctl, package, or service changes. Never run the disposable namespace launcher on physical NICs.

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
3. **Manager exclusivity:** a narrowly scoped, persistent NetworkManager exclusion must target **only** the verified guest NIC. Demonstrate that autoconnect cannot claim that NIC after hotplug, restart or reboot. Do not broadly disable Ethernet management or modify `wlan0`.
4. **Guest starts DOWN:** the guest remains administratively DOWN until guard installation, bypass/topology attestation, correct addressing and independent isolation requirements are satisfied. No service may raise it merely because the cable appears or NetworkManager reconnects. A disconnected cable is not a software interlock.
5. **IPv6 is intentional:** either deny all guest IPv6 with independently verified INPUT/FORWARD/OUTPUT behavior or explicitly isolate and attest any supported IPv6 design. Do not rely on disabling a single sysctl as the sole enforcement layer; reject RA, link-local and forwarding bypasses as applicable.
6. **Guard continuity:** never run full-table bootstrap/replacement on an exposed guest link. Existing hooked base chains must persist across reconciliation; fail to guest-link isolation when guard health or attestation is uncertain. Verify tc/XDP/offload and other bypass paths, not only an nftables table dump.
7. **Failure means no guest exposure:** cover controller crash/SIGKILL, supervisor restart, power loss/reboot, failed or partial manager configuration, USB unplug/replug, guard flush, unexpected interface UP, stale source state and absent conntrack. Require positive read-back of isolation and keep evidence of uncertain isolation as a failure, not success.
8. **No LAN leakage:** separately examine wildcard host listeners, host-originated OUTPUT traffic, route policy/rules and routing to management/protected networks. `check -plan` does not attest all of these.
9. **Private evidence:** preflight and privileged checks must not disclose raw identities into issues, CI logs or shared reports.

## Proposed sequence: separate approvals, not an executable checklist

### Gate A: passive evidence (authorized by read-only reconnaissance)

- Confirm the USB NIC is still cable-disconnected, with no carrier, addresses, routes or bridge membership.
- Capture the live private inventory and run `check -plan` with the private pinned plan. Record all `hazards[]`, `not_assessed[]`, kernel version and NetworkManager evidence.
- Record whether the guest is still UP/IPv6-enabled. **Do not change either condition in Gate A.**
- Confirm physical identity and the management return route, and establish the intended isolated peer and non-overlapping address ranges.

**Gate A pass** means evidence is sufficient to *propose* an implementation; it never means guest activation is permitted.

### Gate B: separately reviewed and authorized host-owner transaction

Before writing a host configuration implementation, produce an exact diff and rollback for a guest-only NetworkManager exclusion; prove interface identity matching does not catch `wlan0` or `eth0`. Independently specify:

- What component owns the guest link at boot, hotplug, normal shutdown and fault.
- How guest administrative DOWN is enforced prior to and independently of the Portcullis daemon.
- How IPv6 is blocked or controlled without relying only on a single sysctl.
- A real supervisor ordering/dependency graph, with guard installation and attestation preceding link activation.
- Read-back assertions after **every** state-changing step and an emergency physical disconnect mechanism.
- A rollback sequence available from an independent console even if SSH or NetworkManager fails.

A privileged change must have an explicit operator approval for this separate phase. Avoid speculative systemd/NetworkManager snippets until a full root-readable configuration audit establishes ownership. No unattended first application to the physical Pi.

### Gate C: disposable compatibility and failure tests

Before hardware packet testing, use only disposable runners to validate the target nftables 1.1.3 semantics, conntrack dependency, guard continuity, IPv4/IPv6 INPUT/FORWARD/OUTPUT, hotplug/reboot assumptions and fault-injection behavior. Test both a proper guard and deliberately missing/modified rules. Treat failures or unknown bypass paths as blockers.

### Gate D: supervised isolated physical acceptance (future, separately approved)

With a confirmed local recovery path and two independently verified, isolated peers, start with guest cable disconnected. Verify the guest is DOWN, guards are installed and attested, and only then explicitly allow a controlled wired guest connection. Exercise DHCP, captive portal, deny-before-grant, scoped temporary grants, expiry, revocation, crash/restart, physical disconnect and recovery. Capture actual packet evidence and guard counters, not just process health. Restore the guest to DOWN and verify absence of unauthorized routes/addresses as a final acceptance step.

## Current stop conditions

- `guest_exposed` or `guest_ipv6_enabled` remains unresolved.
- NetworkManager autoconnect/ownership has not been reviewed and constrained.
- `eth0` peer/cabling and dedicated guest test device have not been independently verified.
- `conntrack` binary is missing and actual kernel/privileged compatibility is untested.
- Independent out-of-band recovery, supervisor and cold-boot policy, and packet/fault evidence are absent.
- An inventory exit 0 or `check -plan` exit 0 is never activation authorization.

## Scope of this PR

This PR records the observed physical hazard and defines testable, staged approval gates. It intentionally makes **no** network configuration or code changes. The next implementation PR should tackle guest-only ownership and fail-closed link lifecycle in isolation, backed by a disposable test harness. Reference: [host preflight](host-preflight.md), [Formnext design contract](formnext-design.md), [repository status](../README.md).
