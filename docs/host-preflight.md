# Pi 5 passive host inventory and topology check (experimental)

**Status:** Unmerged code in [PR #19](https://github.com/thetechbenders/portcullis/pull/19) for [issue #10](https://github.com/thetechbenders/portcullis/issues/10). **Neither command authorizes activating a guest interface.** See proposed [ownership ADR PR #18](https://github.com/thetechbenders/portcullis/pull/18).

## Design: two non-mutating stages

The standard-library-only `portcullis-host` binary performs no sudo, subprocesses, network writes, service installation, nftables changes or device activation.

1. **`inventory`** reads Linux kernel-facing evidence. It emits a timestamped observation, not a safety verdict. Zero exit means the visible inventory was collected without a reported read error. It does **not** mean networking is safe to expose.
2. **`check -plan FILE`** compares that observation with an explicitly pinned, versioned operator plan. It emits `hazards[]`, `not_assessed[]`, `boot_id` (private mode), `observed_at` and a SHA-256 digest of the normalized plan. Exit **0** means no *observed* hazards; exit **1** means at least one was observed; exit **2** means invalid arguments or plan; exit **3** means the JSON output could not be written. None of these codes authorizes guest exposure. An independent privileged attestation and a separately reviewed activation design remain necessary.

By default, both commands **redact sensitive observations**. `-private` includes actual hostname, MACs, addresses, device paths, and the boot ID. MAC-derived `enx...` interface names are anonymized in redacted output; diagnostic finding details are suppressed in redacted checks. Even a shared redacted inventory can expose other interface names, topology and kernel version, so inspect it before sharing. The assessment never includes raw packet contents, tokens, Wi-Fi passwords or SSH material. Keep unredacted reports out of Git history.

## Safe usage

From a separate worktree on Linux with Go 1.26 or newer:

```sh
go test ./internal/hostpreflight ./cmd/portcullis-host
go build -o /tmp/portcullis-host ./cmd/portcullis-host
/tmp/portcullis-host inventory
/tmp/portcullis-host inventory -private
```

To save **private** inventory, use `umask 077` and a directory not shared with the repository:

```sh
umask 077
/tmp/portcullis-host inventory -private > private-inventory.json
```

## Versioned operator plan

This example is **fictional**. First inspect your actual host; do not use these identifiers without independent verification. `pinned_guest_sysfs` is the canonical physical **parent device** path obtained from `/sys/class/net/IFACE/device`, not the unstable `/net/IFACE` child path. Virtual interfaces under `/sys/devices/virtual` are rejected.

```json
{
  "schema_version": 1,
  "selection": {
    "guest": "usb0",
    "uplink": "eth0",
    "management": "wlan0",
    "pinned_guest_mac": "02:22:33:44:55:66",
    "pinned_guest_sysfs": "/sys/devices/pci0000/usb0",
    "pinned_uplink_mac": "dc:a6:32:aa:bb:cc",
    "pinned_uplink_sysfs": "/sys/devices/platform/soc/eth0",
    "pinned_management_mac": "dc:a6:32:bb:cc:dd",
    "pinned_management_sysfs": "/sys/devices/platform/soc/wlan0"
  }
}
```

Save it as `private-host-plan.json` with private file permissions and run:

```sh
/tmp/portcullis-host check -plan private-host-plan.json
```

The plan parser is bounded at 8 KiB, accepts only documented key spellings, rejects duplicate keys (including differently capitalized variants), unknown fields, trailing content, role collisions, invalid interface names, malformed/unicast-invalid MAC pins, virtual or noncanonical sysfs paths, symlinks, FIFOs and plan files not owned by the invoking user or root, or readable/writable by group/others. MACs are canonicalized before comparison.

The tool pins the current MAC and sysfs parent path for all three roles, but **does not** read the permanent hardware MAC through netlink, and cannot establish physical cabling or attachment provenance. A current MAC whose `addr_assign_type` is not permanent is flagged as a possible identity drift. These are gaps to close before host activation.

## Evidence gathered

- Hostname, boot ID, UTC collection time, kernel release, OS and CPU architecture.
- Interfaces, ifindex, current MAC, canonical parent sysfs path, available driver, UP/operstate, master/upper devices, address assignments, MAC assignment type and IPv6 disable/accept-RA sysctls.
- Global and per-interface IPv4/IPv6 forwarding sysctls, including available IPv6 `force_forwarding` controls.
- Kernel procfs visible IPv4/IPv6 routes, with parsing of flags and IPv6 reject/null routes. **IPv4 procfs shows only the main routing table; it is not a complete policy route/rule inventory.** The output explicitly lists these unassessed paths. Route observations are point-in-time, not an atomic kernel snapshot.
- Read/parse errors are explicit findings; missing data is not interpreted as proof of isolation.

`check` currently flags guest UP/loopback/addressed/enslaved or stacked-device state, virtual guest device identity, guest IPv6 and RA state, MAC assignment drift, malformed/mismatched pins, inactive management, role overlap, routes through guest, unexpected active interfaces, enabled forwarding and overlapping management/uplink prefixes excluding link-local addresses. A management default route is allowed in the isolated-uplink pilot, since guest egress is independently restricted by the attested guard; full policy routing is still unassessed.

**Observed hazards are separate from unassessed questions:** NetworkManager/systemd-networkd ownership, IPv4 policy routing tables and rules, exact nftables guard or bypass attestation, physical exposure isolation, recovery, cold boot, SIGKILL and packet-level acceptance. A check returning exit 0 with any `not_assessed[]` entries is useful inventory, **not a deployment approval**.

## Integration and safety limits

- Do not use the read-only tool to install `conntrack`, create systemd units, disable NetworkManager, rename a NIC, change routes or enable forwarding.
- Do not connect a production guest segment or run gateway bootstrap just because `check` finds no observed hazards.
- Read-only evidence can be compared after reboot or USB reconnect using `boot_id`, `observed_at`, plan digest and the private raw observations. If a NIC changes during a scan, the record may be inconsistent: re-run and investigate; no single inventory is atomic.
- The Formnext disposable namespace demonstration is not a public-internet gateway. NAT and postauthorization DNS remain separate work.
- Hardware acceptance requires a separate reviewed topology and supervised procedure preserving management SSH and a recovery path.

For issues found by Claude's independent review, see the review handoff in PR #19 and the separately revised ADR.