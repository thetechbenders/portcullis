# Guest ownership and nftables lifecycle remediation (implementation branch)

**Status: offline candidate code, not deployed or approved for physical activation.**
Evidence baseline: [privileged audit V3](https://drive.google.com/file/d/1qQ63U711djpSzAeJaGs-UUdlv-zccp5p/view).
No host network configuration was changed. The Plugable RJ45 must remain disconnected.

## What this branch changes

- `internal/hostpolicy` renders **private** candidate artifacts scoped to three distinct permanent MAC identities. Rejects missing, multicast, all-zero and overlapping role identities.
- The NetworkManager proposal uses strict `[keyfile] unmanaged-devices=mac:<guest-permanent-MAC>`. The source Netplan Ethernet stanza must be narrowed to the *uplink* permanent MAC, not the string `eth0` alone. Existing Wi-Fi settings and passthrough must be preserved.
- **Default-DOWN remains unsolved for unattended connected boot.** systemd-networkd `ActivationPolicy=` does not supply a valid `.link`-based solution on this NetworkManager-managed host. No fake boot interlock is generated. Initial supervised changes must keep the guest RJ45 disconnected, then use explicitly verified guest-only link closure before any activation.
- The candidate `nftables.service` override clears all stock lifecycle commands and substitutes `ExecStart=/usr/bin/true`, preventing the stock service's `flush ruleset` start/reload/stop actions **if the override is actually loaded**. It intentionally does not install the guard. An unmanaged or manually invoked `nft flush ruleset` remains hazardous.
- The full `inet portcullis_guard` now has an OUTPUT chain. Only guest DHCP responses, established/related IPv4 replies and responses originating at the gateway's DNS/portal service ports are permitted; other host-to-guest traffic is denied by pinned index and reserved interface name. **This does not solve an unknown-name, new-index replacement.**

## Firewall ownership and boot ordering

The guard owner and independent admission boundary must be ready before the guest can come UP. The override is dangerous if installed on its own because the standard nftables loader becomes inert without another verified boot owner. A service restart or manual global flush must be tested under physical closure. Do not imply a service drop-in can prevent deliberate root-level firewall mutation.

No full ruleset flush, uninstall/reinstall, or deletion of unowned nft tables belongs in Portcullis reconciliation. The guard's existing absent-table bootstrap remains a closed-guest operation only. An empty live ruleset is a fail-closed **admission decision** (no guest UP), not evidence of packet filtering.

## Separate physical transaction prerequisites

1. Independently verify local/serial recovery and a bounded rollback from outside SSH. Keep the guest cable physically disconnected. Preserve `wlan0` as management and `eth0` as uplink.
2. Save baseline bytes, owner, mode and generated/effective state for each transaction-owned file in a private directory, including current Netplan, NM and nft service overrides.
3. Confirm fresh physical USB parent, permanent/current MAC, driver, boot generation, ifindex, carrier, routes and address state. Do not commit these identities.
4. Independently validate the **unattended matcher-miss** path with disposable packet tests before claiming pre-packet isolation. A `.link` naming rule, udev helper, or polling owner cannot close a registration race. Until independently proven, restrict the initial transaction to cable-disconnected, supervised work.
5. Apply guest exclusion and narrowly scoped Netplan persistent source as one reviewed, recoverable sequence. Check effective `NetworkManager --print-config`, live ownership, broad autoconnect ineligibility and management route before/after each step. Never restart all networking as a shortcut.
6. Establish verified guard boot ownership before neutralizing `nftables.service`; read back the effective unit commands and guard hooks. Keep physical closure for restarts and fault injection.
7. Read back guest-only DOWN, IPv6 disabled, RA restricted, and full INPUT/FORWARD/OUTPUT guard. Never claim physical isolation from a single snapshot.

**Rollback:** while the RJ45 cable remains disconnected, restore only transaction-owned files, original modes and owners in dependency-safe reverse order; reconcile only the affected service/configuration after verifying the independent console route. Never `flush ruleset`, globally restart network services, or return the broad Ethernet autoconnect profile to a connected guest. On any failed readback or recovery, abort without activating the guest.

## Tests still required before merge or deployment

- Exact-head Go unit, race, vet, fixture-format and disposable netns/e2e checks.
- Demonstrate no regression in DHCP, DNS and portal reachability after OUTPUT filtering. Require positive controls and directional packet counters.
- Wrong and missed guest selectors, broad Netplan profile, competing NM ownership and new-interface default-UP attempts.
- USB rename/re-enumeration, same-VID replacement, reused index, cold boot and manager restart with guest exposure held closed throughout.
- nftables service start/reload/stop, manual global flush, guard corruption, controller SIGKILL, stale grant expiry, IPv6/ARP/L2 and host OUTPUT probes.
- Independent console/rollback and controlled Pi packet tests only after distinct approval.

**No user-facing assertion of physical safety, readiness or production deployment is authorized by this PR.**
