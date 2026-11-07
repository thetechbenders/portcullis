# Guest ownership and nftables lifecycle remediation (implementation branch)

**Status: offline candidate code, not deployed or approved for physical activation.**
Evidence baseline: [privileged audit V3](https://drive.google.com/file/d/1qQ63U711djpSzAeJaGs-UUdlv-zccp5p/view).
No host network configuration was changed. The Plugable RJ45 must remain disconnected.

## What this branch changes

- `internal/hostpolicy` renders **private** candidate artifacts scoped to three distinct permanent MAC identities. Rejects missing, multicast, all-zero and overlapping role identities.
- The NetworkManager proposal now uses strict `[keyfile] unmanaged-devices=type:ethernet;except:mac:<uplink-permanent-MAC>`. It denies *all* Ethernet management except the attested uplink, so missing guest-specific MAC/name matches do not cause automatic NetworkManager adoption. This intentionally prevents other wired devices from being managed until separately reviewed. The source Netplan Ethernet stanza must also be narrowed to the uplink permanent MAC. Existing Wi-Fi settings and passthrough must be preserved.
- A **kernel USB authorization proposal** is now available: `usbcore.authorized_default=0`. Linux blocks USB device driver binding until userspace authorization, so an untrusted USB Ethernet device cannot create a netdev merely by hotplugging. This is a genuine early-stage gate, but it is **global for USB devices**, including USB boot disks and console keyboards. The renderer refuses to propose it unless an independently verified non-USB root filesystem, management path, recovery path, and kernel support are supplied. It does **not** install a boot parameter, authorize a USB device, or prove safe post-authorization behavior.
- **Default-DOWN remains unsolved for unattended connected boot.** systemd-networkd `ActivationPolicy=` does not supply a valid `.link`-based solution on this NetworkManager-managed host. No fake boot interlock is generated. Initial supervised changes must keep the guest RJ45 disconnected, then use explicitly verified guest-only link closure before any activation.
- On the inspected empty-firewall host, the supervised transaction masks the already disabled and inactive stock `nftables.service`. This prevents the unit from running its global flush. The static guard unit requires the mask and an already-active NetworkManager before it installs or readopts an empty guard. See the [Pi runbook](../deploy/pi5/README.md).
- The full `inet portcullis_guard` now has an OUTPUT chain. Only guest DHCP responses, established/related IPv4 replies and responses originating at the gateway's DNS/portal service ports are permitted; other host-to-guest traffic is denied by pinned index and reserved interface name. **This does not solve an unknown-name, new-index replacement.**

## Firewall ownership and boot ordering

The static guard unit has no boot or hotplug trigger. Establish a separate admission boundary and boot owner before any unattended connected use. The stock-service mask does not prevent an administrator from invoking nft directly.

No full ruleset flush, uninstall/reinstall, or deletion of unowned nft tables belongs in Portcullis reconciliation. The guard's existing absent-table bootstrap remains a closed-guest operation only. An empty live ruleset is a fail-closed **admission decision** (no guest UP), not evidence of packet filtering.

## Separate physical transaction prerequisites

1. Independently verify local/serial recovery and a bounded rollback from outside SSH. Keep the guest cable physically disconnected. Preserve `wlan0` as management and `eth0` as uplink.
2. Save baseline bytes, owner, mode and generated/effective state for each transaction-owned file in a private directory, including current Netplan, NM and nft service overrides.
3. Confirm fresh physical USB parent, permanent/current MAC, driver, boot generation, ifindex, carrier, routes and address state. Verify that the uplink MAC exception matches only the onboard `eth0` and not any USB or management device. Do not commit these identities.
4. Independently validate the **unattended matcher-miss** path with disposable packet tests before claiming pre-packet isolation. A `.link` naming rule, udev helper, or polling owner cannot close a registration race. Until independently proven, restrict the initial transaction to cable-disconnected, supervised work.
5. If kernel USB default-deny is selected, validate the complete Pi USB topology, confirm the recovery console is independent of USB, prepare an exact single-line boot parameter diff and offline rollback, then test it only under separately supervised reboot authority. The unattended authorizer must never authorize a guest USB device merely from VID:PID/MAC or the presence of a cable. Kernel authorization must precede fresh network identity and manager checks, but does not grant IFF_UP or gateway admission. Until physical packet tests prove the transition, keep RJ45 disconnected.
6. Apply guest exclusion and narrowly scoped Netplan persistent source as one reviewed, recoverable sequence. Check effective `NetworkManager --print-config`, live ownership, Ethernet-wide unmanaged semantics (including an unknown USB name and MAC), broad autoconnect ineligibility and management route before/after each step. Never restart all networking as a shortcut.
7. Confirm the distro service is disabled and inactive with no other firewall owner. Mask it before creating the pilot guard. Read back the mask, unit state and guard hooks.
8. Read back guest-only DOWN, IPv6 disabled, RA restricted, and full INPUT/FORWARD/OUTPUT guard. Never claim physical isolation from a single snapshot.

**Rollback:** while the RJ45 cable remains disconnected, restore only transaction-owned files, original modes and owners in dependency-safe reverse order; reconcile only the affected service/configuration after verifying the independent console route. Never `flush ruleset`, globally restart network services, or return the broad Ethernet autoconnect profile to a connected guest. On any failed readback or recovery, abort without activating the guest.

## Tests still required before merge or deployment

- Exact-head Go unit, race, vet, fixture-format and disposable netns/e2e checks.
- Demonstrate no regression in DHCP, DNS and portal reachability after OUTPUT filtering. Require positive controls and directional packet counters.
- Wrong and missed guest selectors, broad Netplan profile, competing NM ownership and new-interface default-UP attempts.
- USB rename/re-enumeration, same-VID replacement, reused index, cold boot and manager restart with guest exposure held closed throughout.
- nftables service start/reload/stop, manual global flush, guard corruption, controller SIGKILL, stale grant expiry, IPv6/ARP/L2 and host OUTPUT probes.
- Independent console/rollback and controlled Pi packet tests only after distinct approval.

**No user-facing assertion of physical safety, readiness or production deployment is authorized by this PR.**

## Kernel-authorized default-deny limitations

Linux documents `usbcore.authorized_default=0` as disabling authorization for newly detected USB devices other than root hubs. It is an actual **pre-driver-binding** control on supporting kernels, not an after-the-fact DOWN script. The Pi-specific boot medium, USB host controller topology, recovery input and command-line application have not been tested. A boot parameter is only staged as a string, never written by this branch. A user-space service that reauthorizes every USB device on arrival would destroy this safety boundary. An explicit, reviewable authorizer must treat an absent/misidentified USB device as untrusted, and a separate link owner must keep newly authorized guest netdevs DOWN until the guard is installed and attested. Replug must revoke all prior authorization. The hardware USB authorization gate does not protect a non-USB Ethernet controller or a privileged attacker. Sources: https://docs.kernel.org/usb/authorization.html and https://kernel.org/doc/html/v6.15/admin-guide/kernel-parameters.html.
