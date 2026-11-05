# Read-only physical host preflight (experimental)

**Status:** Unmerged implementation experiment for [P1 issue #10](https://github.com/thetechbenders/portcullis/issues/10). It is **not** a gateway installer, firewall attestor, physical readiness certificate, or permission to connect clients. Read the [proposed ownership ADR](https://github.com/thetechbenders/portcullis/pull/18) and [Formnext design contract](formnext-design.md).

## What it does

The standard-library-only `portcullis-host preflight` subcommand reads Linux kernel exposed interface and route metadata and evaluates an **operator-selected** topology. It performs **no privilege escalation**, does not invoke shell commands or subprocesses, does not write a file, and cannot start a service or configure networking.

Evidence includes hostname, OS/architecture/kernel, interface names/indexes/MACs, canonical sysfs links, drivers (when exposed), interface addresses and administrative/operational state, master and upper devices, and IPv4/IPv6 default-route interface names. Metadata is from `net.Interfaces`, `/sys/class/net`, `/proc/net/route` and `/proc/net/ipv6_route`. Both route files have a bounded read (256 KiB each). An inaccessible or oversized source produces a visible blocker, not a fabricated empty inventory.

Evaluation reports observed hazards (guest interface UP, configured IPs, bridge/upper topology, an IP default route, missing or overlapping interface roles, mismatch with an operator-pinned MAC/sysfs path, management interface down/unaddressed), alongside explicit unresolved **structural** gates: independent guest isolation, systemd/NetworkManager ownership, actual nftables/legacy/tc/flowtable guard attestation, independent management recovery, and physical packet/reboot/crash testing.

**Every report returns `"status": "blocked"` and `"deployment_authorized": false`.** No command-line flag overrides this. Exit code **3** means deliberately blocked, including when no specific observed NIC hazard exists; exit 2 is invalid usage, exit 1 is output failure. Do not interpret exit code 3 as a malfunction or a security audit failure.

## Build (safe, unprivileged)

With Go 1.26 or newer, in an isolated worktree:

```sh
go test ./internal/hostpreflight ./cmd/portcullis-host
go build -o /tmp/portcullis-host ./cmd/portcullis-host
```

The binary can inspect the host without root privileges. Running it does **not** start `portcullisd` or apply any nftables policy.

## Example: inventory without choosing roles

```sh
/tmp/portcullis-host preflight > private-inventory.json
echo "status=$?" # expected: 3
```

This produces full observational evidence and blockers for unselected interfaces. Never commit this JSON, since it can contain real IP addresses, device paths and MACs. Use a private directory and `umask 077` if redirecting output.

## Versioned operator-pinned topology

For repeatable evidence, store a private **plan**, not a live network configuration. A schema-valid plan still never authorizes deployment. These example identifiers are fictional and must not be used without checking the actual Pi.

```json
{
  "schema_version": 1,
  "selection": {
    "guest": "usb0",
    "uplink": "eth0",
    "management": "wlan0",
    "pinned_guest_mac": "02:22:33:44:55:66",
    "pinned_guest_sysfs": "/sys/devices/pci0000/usb0"
  }
}
```

Run a passive comparison using `portcullis-host preflight -plan private-host-plan.json`. The parser limits input to 8192 bytes, rejects unknown fields, trailing data, invalid names, ambiguous roles, bad MACs and unclean non-sysfs identity paths. Combining `-plan` with individual role flags is prohibited. Nothing is applied to the network.

## Example: operator-pinned *candidate* wired topology

Do not copy these names or addresses blindly. First inspect the inventory to identify actual NICs and physical USB paths. The following values are **illustrative only**.

```sh
/tmp/portcullis-host preflight \
  -guest usb0 \
  -uplink eth0 \
  -management wlan0 \
  -pinned-guest-mac '02:22:33:44:55:66' \
  -pinned-guest-sysfs '/sys/devices/pci0000/usb0'
```

This does **not** inspect or modify NetworkManager active-connection ownership; it reports that unresolved dependency as a blocker. It also does not prove an SSH session survives route changes, verify external physical cabling/port isolation, inspect every possible netfilter bypass, establish that the installed kernel guard matches Portcullis's expected schema, or probe any packet. The existing portal demo is *not* general internet access because post-grant DNS recursion and NAT are absent.

A real NIC may already have a link-local IPv6 address, may be administratively UP because its desktop network manager owns it, or may be represented by a different sysfs path after reconnect. These are reasons to **stop and investigate**, not to run commands to hide the evidence.

## Safety, use and follow-up

1. Review the proposed physical topology and independent guest exposure gate before choosing actual devices. Keep the Pi's `wlan0` management route under its existing owner and the USB guest port disconnected.
2. Use this read-only output to inform a reviewable dry-run host adapter configuration. Compare across cold boot and dongle re-enumeration, but do not infer resilience from a single snapshot.
3. Extend the evidence collector **in a separate reviewed change** to include bounded, redacted NetworkManager, systemd-networkd, nftables, iptables, tc/XDP and explicit version attestation. Merely finding the binaries or reading a table does not certify guard correctness.
4. Test lifecycle and ownership state machines in disposable VMs, with positive-control packet probes and fault injection before any installation or physical-interface mutation.
5. Hardware validation requires a separate approved, supervised plan with independent management and a physical disconnect path. Physical AP station identity and DNS/NAT remain separate issues.

The code intentionally has no installer, systemd units, network mutator, capability grants, automatic interface discovery-as-authorization, physical override switch, or network-level test invocation.
