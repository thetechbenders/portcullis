# ADR-001 (proposed): Raspberry Pi 5 physical interface ownership and safe boot

**Status:** Proposed / design-only. **Issue:** [#10](https://github.com/thetechbenders/portcullis/issues/10).  
**Date:** 2026-11-05. **Target:** Pi 5, Raspberry Pi OS Trixie, ARM64.  
**Decision authority:** Requires operator review; **no physical deployment authorized**.

## Context and scope

The merged Formnext slice implements a privileged controller, exact nftables guard attestation, bounded kernel grants, revocation and degraded isolation in **disposable network namespaces**. Native Pi 5 compilation and ordinary unit tests are recorded by the separate ARM64 bring-up work. Neither demonstrates safe ownership of a physical interface from cold boot.

The current `portcullisd bootstrap` requires a DOWN guest link and an absent guard table. `run` attests an installed guard and revokes inherited grants. Degraded isolation reads back administrative DOWN status but that observation is point-in-time, may fail, and cannot stop another privileged actor from reactivating the link. A process crash leaves existing kernel grants effective until their own timeout, at most 15 minutes. Those facts must remain visible in the physical deployment contract.

This ADR proposes a host adapter and test strategy. It does **not** change the core controller, install services, assign interfaces, modify nftables, expose an AP, or authorize testing on the real Pi.

References: [Formnext design](../formnext-design.md), [integration evidence](../formnext-integration.md), [ARM64 report](../pi5-arm64-bringup.md) (on the unmerged bring-up branch), [#5](https://github.com/thetechbenders/portcullis/issues/5), [#9](https://github.com/thetechbenders/portcullis/issues/9), [#11](https://github.com/thetechbenders/portcullis/issues/11), [#12](https://github.com/thetechbenders/portcullis/issues/12), [#13](https://github.com/thetechbenders/portcullis/issues/13).

## Proposed decision

**A host adapter, independent of the grant/controller state machine, owns only an explicitly nominated guest interface and its boot-time exposure.** Its default is *not exposed*. It can request exposure only after an independent preflight confirms physical topology, persistent guard hooks, controller readiness, and the absence of known bypass paths. The guest link must be isolated before first installation, migration, or recovery. Neither successful `systemctl start` nor a daemon status string constitutes packet isolation evidence.

This requires two different protections:

1. **Software deny:** An installed, continuously attested, hooked nftables guard, with no permissive fallback or silent replacement. The controller's kernel grant timeouts bound residual authority after a crash, but do not instantly revoke it.
2. **Independent exposure gate:** During initial boot/migration/failure experiments, the guest cable is physically disconnected (or the external access port/AP power is independently disabled). On a production candidate, a *reviewed independent* gate must prevent guest exposure during any period in which the kernel guard has not been verified. Interface DOWN alone is not an independent hardware boundary.

If the independent gate is absent, the system must remain **lab-only**. The adapter cannot truthfully claim unconditional fail-closed operation from systemd ordering alone.

### Candidate Pi topology for the first supervised wired experiment

```text
Hephaestus -- home management LAN/Wi-Fi -- Pi wlan0 (management only)
                                           |
                                           +-- Pi eth0 (candidate uplink)
                                           |
                                           +-- USB GbE (candidate guest port)
                                                         |
                                                one controlled wired client
```

This is an **illustrative candidate**, not an allocation: no USB NIC identifier, network addressing, cabling, route, firewall, AP, or uplink has been approved or configured. Use explicit stable physical identifiers (MAC **plus** sysfs/driver/port identity and expected link topology), not `eth1` or `enx*` guessed from enumeration. Refuse missing, renamed, duplicated, enslaved or ambiguous interfaces. Reject any guest interface that overlaps the management path, has an existing network-manager connection, or belongs to an unexpected bridge/VLAN/macvlan/ipvlan topology.

`wlan0` must remain a separately recoverable management path, never silently adopted as an uplink for guest forwarding. If management and uplink share the same home router/L2, protected management subnets and routing collision checks remain mandatory. Guest egress must be constrained to the explicitly attested uplink. An external AP/Slate AX and shared wireless guests are **not** part of the first wired test: client-station provenance and local client isolation belong to [#11](https://github.com/thetechbenders/portcullis/issues/11). Public internet access additionally requires controlled DNS/NAT [#13](https://github.com/thetechbenders/portcullis/issues/13); the current demo proves only access to a designated lab destination.

## Ownership contract

| Component | Intended owner | Refuse / constrain |
| --- | --- | --- |
| Existing management Wi-Fi, SSH and routes | Existing NetworkManager configuration, outside Portcullis | Adapter must not edit, bounce, capture, or remove management connections |
| Explicit guest NIC | Host adapter only after opt-in | No NetworkManager autoconnect, DHCP client, bridge membership, alternate address/route, or implicit systemd-networkd ownership |
| Explicit uplink NIC | Reviewed existing host owner, with Portcullis enforcement constraints | No automatic fallback to management interface or default-route discovery as authorization |
| Persistent `inet portcullis_guard` | Controller bootstrap **only while independently isolated**, attested thereafter | Never `nft flush ruleset`, recreate hooked chains live, import foreign state, or replace a table during service restart |
| Runtime grant sets | Privileged controller | Bounded, atomic updates and kernel readback; no startup restoration of forwarding authority |
| Guest DHCP/DNS/HTTP | Controller/portal after guard attestation | Guest interface-specific sockets; never wildcard or management listeners |
| Third-party firewalls, Docker, legacy iptables, nft/tc/XDP | Other owners; preflight inventories and monitors them | Known bypass, unexpected hooks/flows, unsupported conflicts and reloads halt exposure; do not silently rewrite another owner's rules |
| Local operator / recovery | Human operator, independent management path | No guest-facing administration or remote shell service added by the adapter |

A NetworkManager "unmanaged guest" profile or per-device exclusion would be part of a **separately reviewed install**, not a prerequisite to writing this ADR. Never disable NetworkManager globally. Service-order dependencies are necessary but cannot prevent all early-boot races, privileged administrator changes, flow offload, firmware/AP bypass, or outside-of-namespace forwarding.

### Preflight inventory, read-only and explicit

The eventual `portcullis-host preflight --dry-run` should produce a bounded, redacted machine-readable report and refuse all ambiguous cases:

- Pi/OS/kernel/build identifier and 16K-page ARM64 compatibility; guard schema/version expected by the binary.
- Physical NIC identity: name, permanent/current MAC, interface index, sysfs device path, driver, carrier, master/uppers, expected link peer if independently known, NetworkManager/systemd-networkd ownership.
- All IPv4/IPv6 addresses, routes, rules, DHCP clients, forwarding sysctls, RA/DHCPv6, expected guest/uplink/management CIDRs, collision with localhost, private/protected, link-local, CGNAT and VPN destinations.
- Entire effective nftables base-chain/flowtable inventory and compatibility with legacy iptables, Docker/firewalld, tc, XDP, VLAN/bridge/macvlan/ipvlan and hardware acceleration. Unknown or opaque forwarding paths fail preflight.
- Named management recovery method and independent guest exposure gate; positive readback of management reachability must not be inferred solely from `wlan0 UP`.
- No secrets in evidence: redact tokens, Wi-Fi PSKs, SSH material and raw guest payloads. Write output with restricted permissions.

The inventory is not proof of future isolation. Any change in links, firewall ownership or policy versions invalidates the authorization to expose the guest interface.

## Conceptual boot and shutdown protocol (not runnable units)

1. **Cold/power-loss start:** Independent guest exposure gate remains OFF. Management remains under its existing owner; Portcullis takes no management interface actions. A missing or failed prerequisite leaves the gate OFF. Software cannot guarantee pre-userspace link isolation unless external gating or physical disconnection provides it.
2. **Preflight:** Resolve pinned physical interfaces and address plan; reject any drift, collision, unexpected manager, forwarding path, insecure neighbor route, schema mismatch, or absent independent isolation mechanism.
3. **Guard installation:** While guest is physically isolated and administratively DOWN, bootstrap the guard **only if it is absent**, then read back exact hook/policy/set structure and full bypass/topology attestation. An existing unfamiliar table is an error; do not flush/replace it.
4. **Controller startup:** Attest, revoke inherited grants, confirm absence of authorization and start the controller/portal. Readiness must mean verified kernel state **and** live restricted services, not merely process start or PID file creation.
5. **Operator-controlled exposure:** Only with positive, independent evidence and explicit test approval may the adapter enable the nominated guest link (and later an external port gate). After exposure, monitor guard, link, ownership and gateway state; any uncertainty makes the state `isolation_unconfirmed` and denies further grants.
6. **Graceful stop/restart:** First isolate the guest exposure path and independently verify it; only then stop network services or perform offline version migration. Keep baseline deny. Controller stop without verified isolation does not authorize removing the guard.
7. **Crash / SIGKILL / failed start:** Do not auto-expose or reconfigure links to "recover". Existing timed grants can remain until kernel expiry (maximum 15 min): do not report instantaneous revocation from daemon death alone. Link-down retries stop when the daemon dies. A separate independent exposure gate or hardware intervention is needed to make stronger immediate-isolation claims.
8. **Firewall reload / NetworkManager reconnect / USB NIC change:** Treat as a possible loss of authority. Do not rebuild a live table as a fallback. If a controlled isolated guest exposure gate cannot be confirmed OFF, classify safety **unconfirmed** and require physical operator intervention.
9. **Rollback / uninstall:** First disconnect the guest externally; verify management route and kernel deny remain intact. Stop the adapter, revoke grants and isolate link; remove only version-matched Portcullis-managed artifacts while independently isolated. Unknown or foreign state blocks automatic removal; retain deny and emit explicit recovery instructions. Never modify a management connection as an "uninstall cleanup".

Expected systemd dependency graph: a *preflight/guard-attestation* prerequisite precedes a controller readiness check, which precedes a separately gated guest exposure action; failures of any predecessor inhibit exposure. This is an ordering contract, **not** a claim that systemd alone provides early-boot physical isolation. Unit names, capabilities, sandboxing, `BindsTo`/`PartOf` policies and network management integration must be implemented and tested in a later PR, not inferred from this design.

## Isolation and recovery status contract

Report two independent axes:

- **Enforcement:** `guard_attested`, `guard_invalid`, `guard_unknown`; include last successful readback time, schema, interface binding and bounded-grant snapshot.
- **Exposure:** `physically_isolated_confirmed`, `admin_down_confirmed`, `isolation_unconfirmed`. Administrative DOWN is not equivalent to independently confirmed physical isolation. A successful past status is not permanent proof.

Any transition away from an attested guard refuses new grants. An operator interface must not display `safe`, `isolated` or `fail-closed` solely because degraded mode was entered. Preserve the explicit confirmed/unconfirmed distinction from [#9](https://github.com/thetechbenders/portcullis/issues/9); do not invent a sensor that can distinguish physical unplugged state without a trustworthy measurement source.

Recovery requires a local console or separately functioning management link, a documented physical guest disconnect, a full policy snapshot and deliberate repair. Never suggest temporarily disabling host firewall enforcement, using `nft flush ruleset`, or changing SSH authentication to restore access.

## Test gates and evidence

**Gate 0: Docs/design (this PR).** Security/design review agrees on interface identity, independent gate, management topology, state machine, owners and rollback. No package install or runtime mutation.

**Gate 1: Disposable VM/namespace acceptance (future code PR).** The host adapter's state machine is tested without physical devices. Every denied probe needs a positive control showing packets would otherwise have reached the test destination; record guarded-direction drop counters and state readback. Fault matrix:

| Injection | Required result |
| --- | --- |
| Guard missing, dormant, wrong hook, wrong interface, stale schema | No exposure; no authorization; explicit invalid state |
| Boot services delayed, reordered or crashing before ready | No guest delivery; no permissive fallback; independent exposure remains OFF |
| Controller SIGKILL/crash during bounded grant | Existing grant authority honestly reported until kernel expiry; do not falsely claim immediate stop without an independent gate |
| nftables reload/removal, legacy rules/flowtable/tc/XDP drift | Refuse service/exposure; declare isolation unconfirmed if the independent gate cannot be verified |
| NetworkManager reactivates a guest or uplink changes | Treat as exposure violation; prevent continuing grants; fail test if management is disturbed |
| Interface disappears/re-enumerates, unexpected bridge/VLAN/upper | Refuse pinned identity; no opportunistic substitution |
| IPv6 becomes enabled, route/VPN changes, protected-prefix collision | No IPv6 leak, no guest-to-management path, no alternate uplink |
| Partial upgrade, rollback, stale table, power loss | Preserve independent isolation; offline migration only; no table-replacement authorization |
| Explicit revoke, kernel expiry, long-lived TCP/UDP | Bidirectional loss of delivery with positive recovery controls, including existing flows |

A CI status or in-namespace packet test is **not** a physical hardware safety certificate.

**Gate 2: Supervised Pi dry-run (later explicit approval).** Read-only inventory first; confirm live independent management and local recovery. Install nothing and change no interface until an operator reviews the proposed exact device identifiers, subnets and rollback script. Missing `conntrack` is a blocker for the full privileged test until separately approved installation.

**Gate 3: Single-client wired pilot (later explicit approval).** Use a physically disconnected guest link until preflight/guard readiness. Test both unauthorized and authorized delivery to a *controlled test destination*, and revoke/expiry/reboot/crash paths. Require operator at the device with ability to remove the guest cable and restore power. Collect reproducible logs without secrets. Any failed/ambiguous isolation ends the pilot.

**Gate 4: Shared AP/internet (separate issue acceptance).** Do not attach real wireless guests without [#11](https://github.com/thetechbenders/portcullis/issues/11) association/trust model and client isolation. Do not claim general internet access until [#13](https://github.com/thetechbenders/portcullis/issues/13) post-grant DNS/NAT and [#12](https://github.com/thetechbenders/portcullis/issues/12) policy migration pass. Venue radio/network permission is an independent requirement.

## Alternatives and open questions

- **Rely on interface DOWN + systemd ordering:** Rejected as sufficient; early boot, manager reactivation, process death and other privileged actors can bypass the promise.
- **Run the VM namespace demo directly on Pi host interfaces:** Rejected. Namespace links, packet assumptions and lifecycle ownership do not translate directly.
- **Use the Pi's sole current Wi-Fi interface as guest AP:** Deferred. It risks management loss and has no trusted station/association evidence today.
- **Use a separate wired guest dongle, plus independent guest-side disconnect:** Preferred for the first controlled pilot; still requires verification of stable adapter identity and external isolation.
- **Externally control guest switch port or AP power from a separate controller:** Candidate for eventual autonomous failsafe, but introduces a new trusted component and needs failure-mode testing. No particular product or protocol chosen.

Open review decisions: exact adapter/guest NIC, whether an independently controllable external gate exists, how to attest its state, Wi-Fi management path resilience, uplink route/source selection, whether any firewall manager other than Portcullis is active, and packaging of a non-destructive installer/uninstaller.

## What this ADR does **not** accomplish

It does not satisfy issue #10's implementation or acceptance gates, install packages, prove reboot isolation, guarantee crash-time immediate denial, or authorize physical network changes. The next code PR should implement the **dry-run preflight and a disposable VM fault harness first**, with a strict no-mutation default, before proposing actual host systemd units or an installer.
