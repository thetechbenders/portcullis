# ADR-001 (proposed): Raspberry Pi 5 physical interface ownership and safe boot

**Status:** Revised proposed design after independent review / design-only. **Issue:** [#10](https://github.com/thetechbenders/portcullis/issues/10).  
**Date:** 2026-11-05. **Target:** Pi 5, Raspberry Pi OS Trixie, ARM64.  
**Decision authority:** Requires operator review; **no physical deployment authorized**.

## Context and scope

The merged Formnext slice implements a privileged controller, exact nftables guard attestation, bounded kernel grants, revocation and degraded isolation in **disposable network namespaces**. Native Pi 5 compilation and ordinary unit tests are recorded by the separate ARM64 bring-up work. Neither demonstrates safe ownership of a physical interface from cold boot.

The current `portcullisd bootstrap` requires a DOWN guest link and an absent guard table. `run` attests an installed guard and revokes inherited grants. Degraded isolation reads back administrative DOWN status but that observation is point-in-time, may fail, and cannot stop another privileged actor from reactivating the link. A process crash leaves existing kernel grants effective until their own timeout, at most 15 minutes. Those facts must remain visible in the physical deployment contract.

This ADR proposes a host adapter and test strategy. It does **not** change the core controller, install services, assign interfaces, modify nftables, expose an AP, or authorize testing on the real Pi.

References: [Formnext design](../formnext-design.md), [integration evidence](../formnext-integration.md), [ARM64 report in PR #17](https://github.com/thetechbenders/portcullis/pull/17) (unmerged), [#5](https://github.com/thetechbenders/portcullis/issues/5), [#9](https://github.com/thetechbenders/portcullis/issues/9), [#11](https://github.com/thetechbenders/portcullis/issues/11), [#12](https://github.com/thetechbenders/portcullis/issues/12), [#13](https://github.com/thetechbenders/portcullis/issues/13).

## Proposed decision

**A host adapter, independent of the grant/controller state machine, owns only an explicitly nominated guest interface and its boot-time exposure.** Its default is *not exposed*. It can request exposure only after an independent preflight confirms physical topology, boot-restored guard hooks, controller readiness, and the absence of known bypass paths. The guest link must be isolated before first installation, migration, or recovery. Neither successful `systemctl start` nor a daemon status string constitutes packet isolation evidence.

This requires two different protections:

1. **Software deny:** A hooked nftables guard, installed before the guest can be managed or exposed, with no permissive fallback or silent replacement. **nftables state is lost at every reboot.** Persistence across daemon crashes is not persistence across power cycles. The controller's kernel grant timeouts bound authority after a process crash, but do not instantly revoke it.
2. **Exposure control:** For the first physical pilot the guest cable stays disconnected until explicit operator acceptance. For unattended operation, a reviewed early-boot, manager-exclusion and guard-readback sequence is required. An external hardware gate is a possible stronger control, **not automatically a universal production prerequisite**. Interface DOWN is useful kernel isolation when no other manager can raise it, but is not proof that no privileged actor or service can reactivate it.

Without a demonstrated unattended early-boot deny mechanism and explicit threat-model review, the system remains **lab-only**. Neither systemd ordering nor an unverified external gate is by itself an unconditional fail-closed guarantee.

### Candidate Pi topology for the first supervised wired experiment

```text
Hephaestus -- home management LAN/Wi-Fi -- Pi wlan0 (management only)
                                           |
                                           +-- Pi eth0 -> dedicated, isolated test peer (first pilot)
                                           |
                                           +-- USB GbE (candidate guest port)
                                                         |
                                                one controlled wired client
```

This is an **illustrative candidate**, not an allocation: no USB NIC identifier, network addressing, cabling, route, firewall, AP, or uplink has been approved or configured. Use explicit stable physical identifiers (MAC **plus** sysfs/driver/port identity and expected link topology), not `eth1` or `enx*` guessed from enumeration. Refuse missing, renamed, duplicated, enslaved or ambiguous interfaces. Reject any guest interface that overlaps the management path, has an existing network-manager connection, or belongs to an unexpected bridge/VLAN/macvlan/ipvlan topology.

`wlan0` must remain a separately recoverable management path, never silently adopted as an uplink for guest forwarding. For the first wired pilot the uplink must attach to a **dedicated test peer on a disjoint segment**, not to the home LAN. Any later shared-router/L2 topology requires separately reviewed protected-prefix and routing checks. Guest egress must be constrained to the explicitly attested uplink. An external AP/Slate AX and shared wireless guests are **not** part of the first wired test: client-station provenance and local client isolation belong to [#11](https://github.com/thetechbenders/portcullis/issues/11). Public internet access additionally requires controlled DNS/NAT [#13](https://github.com/thetechbenders/portcullis/issues/13); the current demo proves only access to a designated lab destination.

## Ownership contract

| Component | Intended owner | Refuse / constrain |
| --- | --- | --- |
| Existing management Wi-Fi, SSH and routes | Existing NetworkManager configuration, outside Portcullis | Adapter must not edit, bounce, capture, or remove management connections |
| Explicit guest NIC | Host adapter only after opt-in | No NetworkManager autoconnect, DHCP client, bridge membership, alternate address/route, or implicit systemd-networkd ownership |
| Explicit uplink NIC | Reviewed existing host owner, with Portcullis enforcement constraints | No automatic fallback to management interface or default-route discovery as authorization |
| In-memory `inet portcullis_guard` | Early-boot host guard unit restores the exact versioned guard after each reboot, strictly before guest manager/exposure; controller attests thereafter | Never `nft flush ruleset`, recreate hooked chains live, import foreign state, or replace a table during service restart. Unit must fail closed on mismatch |
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


## Revised boot-time ownership and bypass contract

The initial draft failed to distinguish reboot from daemon restart. **The kernel does not persist nftables tables through reboot.** The next adapter design must include an isolated early-boot guard installation step and independent network-manager prevention of guest autoconnect, DHCP clients and RA acceptance before any link may be raised.

A candidate systemd one-shot ordering is `DefaultDependencies=no`, `Before=network-pre.target NetworkManager.service`, `Wants=network-pre.target`, but **these values are design inputs, not approved unit files**. They cannot alone defeat udev activation, a manager not covered by the unit graph, or an external link already connected before userspace. Treat manager ownership, interface naming, security and restart semantics as a combined dependency, and test them under a disposable VM with cold boot and delayed-service fault injection.

- **Device binding:** The present guard has guest-specific `iifname` matches and `policy accept` base-chain defaults. An unrecognized guest interface name can therefore escape its intended rules. An explicit `.link` name pinned to a physical device identity may reduce accidental rename, but is not an independent kernel enforcement guarantee. Consider `policy drop` for the **dedicated** gateway's forward chain with deliberately scoped exceptions, and test legitimate host forwarding before changing [#12](https://github.com/thetechbenders/portcullis/issues/12)'s guard schema. The host INPUT path separately needs review; an indiscriminate INPUT drop risks management lockout.
- **NetworkManager:** Inventory the actual Pi's `no-auto-default`, active profiles, match rules, IPv4 DHCP, IPv6 RA/autoconnect and any cloud-init/netplan/systemd-networkd ownership. The guest device needs narrowly scoped unmanaged handling, not a global NetworkManager disable. This must be validated read-only before any installation.
- **Forwarding ownership:** Explicitly decide when `net.ipv4.ip_forward` may be enabled and who reverts it. A reviewed systemd failure/finalization handler could disable IPv4 forwarding, flush grants and bring the *guest* down after SIGKILL. This is a **host-global** knob: using it on a host with unrelated forwarding would be disruptive and is not automatically safe. IPv6 forwarding remains disabled for MVP. A process crash does not itself immediately remove existing kernel grants.
- **nftables.service:** Verify whether a distro service is enabled and whether its ruleset starts with `flush ruleset`. Reloading it can destroy the Portcullis guard and expose the interface if another component raises/owns the link. Ensure the production ownership plan either prevents that interaction or proves isolation and closed failure on reload. Never repair by reconstructing active hooked chains without an isolated guest.
- **Input/output:** A forwarding DROP alone does not prevent host INPUT on an unexpected guest NIC name. Review separately whether guard rules can constrain unknown device ingress, and how to prevent host-initiated mDNS/LLMNR or other outbound leakage to the guest. Do not add broad rules to the current host before reviewing local services and recovery.
- **Backend compatibility:** Existing disposable GitHub tests used nftables 1.0.9; the Pi has nftables 1.1.3. Add an independent Debian Trixie disposable runner to verify the exact policy's serialization and attestation, refusing unfamiliar schema rather than silently adopting it.
- **Physical gate decision:** The independently controlled access-port or power gate remains an option for a stronger threat model, not an unexamined prerequisite. For an initial supervised single-client wired pilot, physical unplug/replug is the operator gate. Distinguish a timestamped *operator assertion* of unplugging from instrumented `physically_isolated_confirmed`: never invent independent sensing.

## Required evidence pipeline

1. **Inventory:** Unprivileged, redacted-by-default observations with boot ID, timestamp, kernel/routing context and interface evidence. No authorization field or "safe" conclusion.
2. **Plan check:** A pure function of pinned plan plus observation, yielding `hazards[]` and `not_assessed[]` separately. Exit zero means zero *observed* hazards, **not** deployment approval.
3. **Privileged, read-only attestation:** Exact guard schema/hooks and bypass paths, nft version, manager-owned device topology, readback of link state; include the boot ID and hashes of plan and attested ruleset.
4. **Operator authorization:** A distinct decision tied to boot ID, plan hash, attestation digest and expiry. Any drift or reboot invalidates the record. A human approves exact NICs, cabling and rollback.
5. **Mutating activation:** The sole component permitted to expose the guest, after immediately revalidating stages 1-3 and the operator decision. Must have a specifically tested cleanup/failure path.

A positive test run of an unprivileged inventory tool is never evidence that cold-boot packet isolation was achieved. Neither PR #18 nor #19 implements stages 3-5.

## Alternatives and open questions

- **Rely on interface DOWN + systemd ordering:** Rejected as sufficient; early boot, manager reactivation, process death and other privileged actors can bypass the promise.
- **Run the VM namespace demo directly on Pi host interfaces:** Rejected. Namespace links, packet assumptions and lifecycle ownership do not translate directly.
- **Use the Pi's sole current Wi-Fi interface as guest AP:** Deferred. It risks management loss and has no trusted station/association evidence today.
- **Use a separate wired guest dongle, plus independent guest-side disconnect:** Preferred for the first controlled pilot; still requires verification of stable adapter identity and external isolation.
- **Externally control guest switch port or AP power from a separate controller:** Candidate for eventual autonomous failsafe, but introduces a new trusted component and needs failure-mode testing. No particular product or protocol chosen.

Open review decisions: exact adapter/guest NIC, whether an independently controllable external gate exists, how to attest its state, Wi-Fi management path resilience, uplink route/source selection, whether any firewall manager other than Portcullis is active, and packaging of a non-destructive installer/uninstaller.

## What this ADR does **not** accomplish

It does not satisfy issue #10's implementation or acceptance gates, install packages, prove reboot isolation, guarantee crash-time immediate denial, or authorize physical network changes. The next code PR should implement the **dry-run preflight and a disposable VM fault harness first**, with a strict no-mutation default, before proposing actual host systemd units or an installer.
