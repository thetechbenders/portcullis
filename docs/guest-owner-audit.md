# Guest NIC manager ownership: read-only audit checkpoint

**Status: experimental diagnostic only. No physical activation, no NetworkManager configuration changes, no approval of ADR-001.**

This command is the next evidence-gathering step before deciding on a persistent, narrowly scoped guest-device exclusion and an independent early-boot/default-DOWN mechanism:

```sh
go build -o /tmp/portcullis-owner-audit ./cmd/portcullis-owner-audit
/tmp/portcullis-owner-audit check -plan private-host-plan.json
```

The plan must be private (0600), owner-validated, and use the same physical role pins as `portcullis-host check`. The command collects the existing read-only host preflight snapshot, evaluates its hazards, and invokes only the following NetworkManager observation:

```text
/usr/bin/nmcli -t -f GENERAL.NM-MANAGED,GENERAL.AUTOCONNECT,GENERAL.CONNECTION device show <pinned-guest-interface>
```

Its executable path is fixed. It never asks NetworkManager for a profile dump, secrets, active connection UUID, IP configuration, or other unrestricted fields. The query has a four-second deadline, a 4096-byte output cap, and refuses malformed, incomplete, duplicate or unknown values. Command stderr is discarded. No raw nmcli output, connection names, interface identifiers, private plan, boot ID, addresses, or sysfs path is emitted by the command; the JSON report provides only fixed finding codes and fixed unassessed descriptions. It calls no write API, `nmcli device set`, `nmcli connection modify`, service manager, `ip link`, or nftables. There is no `-private` override.

Exit codes: **0** no hazards *observed*; **1** observed managed/autoconnect/active connection, host-preflight hazard, unavailable/ambiguous manager output; **2** invalid/missing private plan or arguments; **3** output failure. Even exit 0 **is not permission to connect or raise a guest NIC**.

## Interpretation

- **`guest_networkmanager_managed`** means NetworkManager reports the device under its control; autonomous activation is plausible.
- **`guest_networkmanager_autoconnect`** means its device-level autoconnect is enabled; profile-level autoconnect is **not** proven off by a negative result.
- **`guest_networkmanager_connection_active`** means there is an active connection.
- **`networkmanager_observation_unavailable`** means the command failed, reported an unsupported value, returned insufficient fields, or was unavailable. **Never infer unmanaged from absence.**
- **`host_preflight_hazard`** means one or more pinned-plan hazards exist in the kernel-facing passive snapshot. Run `portcullis-host check -plan` separately in a private terminal for detail.

The output always lists unknown requirements, including root-visible effective NetworkManager configurations and profiles, other interface managers, immutable physical identity, boot/hotplug timing, independent default-DOWN enforcement, recovery and managed-state rechecks. A device reporting `GENERAL.NM-MANAGED:no` is **not** evidence that all managers are excluded or that an unauthorized privileged actor cannot raise it.

## What we must independently establish before any host write

The proposed persistent NetworkManager exclusion, potentially using a physically scoped `keyfile.unmanaged-devices` selector, needs a **separately authorized privileged read-only** inspection of effective configuration and existing profile precedence. Per-device `managed` and udev `NM_UNMANAGED` rules can have different override semantics. NetworkManager's documentation describes `keyfile.unmanaged-devices` as strictly unmanaged, unlike the overridable `device*.managed` configuration. Other managers may ignore NM settings entirely. No exact guest match or rollback command is safe to select without that audit.

Before producing a deployable installer, review a precise guest-only configuration diff, selector failure tests, preserved management `wlan0` route and SSH return path, separate local-console recovery, a bounded automatic revert mechanism where feasible, and deterministic boot ordering of guard installation before any interface activation. Test both the correct matcher and an *intentionally missed* matcher. A udev hotplug helper issuing DOWN **after registration** cannot by itself prove that no packet escaped between registration and enforcement. Do not treat a disconnected cable, NetworkManager exclusion alone, or a successful audit as the independent exposure gate.

The next enforceable implementation needs explicit host ownership and rollback authorization. It must not blindly touch `wlan0`, disable NetworkManager globally, install units on the Pi, or bootstrap a guard while a guest is exposed.

References: [ADR-001](adr/0001-pi5-physical-interface-ownership.md), [physical ownership contract](pi5-guest-nic-ownership.md), and [host preflight](host-preflight.md).
