# Pi 5 supervised first installation

Keep the guest RJ45 physically disconnected throughout installation, readback
and rollback. Use an independently demonstrated local or serial login for the
transaction, and verify a second SSH connection through `wlan0`. Leave the
onboard uplink disconnected during this stage. The endpoint is an administratively
DOWN guest with an empty, attested guard. The controller and portal stay stopped.
Do not set `usbcore.authorized_default=0` in this pilot.

## Private preparation

1. Build the checked-out commit with
   `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /PRIVATE/bin/ ./cmd/...`.
   Record the commit and hash the delivered files. Build `portcullis-hostprep`
   and `portcullis-policy` for the preparation machine as well.
2. Inspect the actual protected Netplan sources in all three precedence
   directories, effective and active NetworkManager ownership, the SSH return
   route, service files and firewall inventory. The transaction below assumes
   the stock nftables unit is disabled and inactive, the ruleset is empty, and
   there is no existing Portcullis installation. A different owner or policy
   needs its own scoped migration.
3. Record the boot ID, physical ancestry, current and permanent MACs, drivers,
   ifindices, USB VID/PID, guest IPv6 settings, and SSH peer privately. The
   installed `pilot-pins.json` contains `boot_id`, `ssh_peer`, and `guest`,
   `uplink`, and `management` objects with `device` (resolved sysfs path),
   `mac`, and `ifindex`. Add `usb_id` (two strings) and `original_ipv6`
   (`accept_ra` and `disable_ipv6`, both strings) to the guest object.
   A different boot or interface generation requires fresh inspection.
4. Write an owner-only JSON file with `GuestMAC`, `UplinkMAC` and
   `ManagementMAC`. Run `portcullis-hostprep -identities FILE -out NEW_DIR`.
   Its strict NetworkManager rule excludes Ethernet except the verified
   onboard uplink. Compare it with the effective config and preserve unrelated
   settings. The Wi-Fi device falls outside the Ethernet selector.
5. Replace only the broad match in the existing persistent wired Netplan
   definition. Keep its UUID, DHCP settings and other profile properties.
   Use the rendered onboard name and permanent MAC match and
   `activation-mode: manual` so this installation cannot autoconnect the wired
   profile. Keep the existing Wi-Fi source byte-for-byte. Run
   `python3 validate-netplan.py BASELINE_ROOT CANDIDATE_WIRED_YAML pilot-pins.json`
   to generate baseline, candidate and restored profiles in a temporary root.
   Review the generator's NetworkManager device configuration as well as the
   generated profile scope.
6. Prepare a private `config.json` with the pinned guest name and `eth0`.
   Pick an unused guest subnet. The closed pilot assigns no addresses.
   Run `portcullis-policy -guard-config config.json > guard.nft` and validate
   it with `nft --check --file guard.nft` on the Pi while the table is absent.
   On an offline machine supply `-guest-ifindex INDEX` from the private pins.
   The closed guard commands require `ip` and `nft`. The future connected
   controller also requires `conntrack`.

## Installation after explicit approval

Work from the verified console with both Ethernet cables disconnected. Recheck
the complete source hashes and runtime assumptions before proceeding. Use
root-only staging and backup directories. Keep original bytes, ownership and
modes with `cp -a`. Refuse destination symlinks or unexpected preexisting
files, masks, profiles or units.

1. Save the exact wired YAML and hash the Wi-Fi sources. Record current NM
   config, SSH route, guest flags, sysctls, nftables unit states and ruleset.
   Confirm the stock `nftables.service` is disabled/inactive and its mask
   destination absent. It must stay inactive throughout. Use
   `systemctl --no-reload mask nftables.service`. The mask stops future stock
   start/restart jobs from executing the global flush without pretending
   that a replacement firewall loaded. It has no effect on other tables.
2. Install the scoped NM snippet in `/etc/NetworkManager/conf.d/` and the
   validated replacement at the original wired YAML path. Leave Wi-Fi source
   files and existing active connections alone. Run `netplan generate`,
   `nmcli general reload conf`, then `nmcli connection reload`. Verify that
   the effective NM configuration includes the exact strict exclusion and
   that the live guest is unmanaged and both other roles remain managed.
   Confirm the SSH return route and second connection. No NM restart or
   `netplan apply` is needed.
3. Install the verified ARM64 `portcullisd` in `/usr/local/bin/`, the helper
   as `/usr/local/libexec/portcullis-pilot-closed`, and the config and pins in
   `/etc/portcullis/` with root-only access. Run the helper with
   `close /etc/portcullis/config.json`. It verifies the pinned roles,
   ownership, and carrier before setting the guest DOWN and reads back
   guest flags, addresses, routes and management routing afterward.
4. Install `portcullis-guard.service` under `/etc/systemd/system/`, run
   `systemctl daemon-reload` and `systemctl start portcullis-guard.service`.
   The static unit requires an already-running NetworkManager and never
   pulls it in. It requires the stock nftables service to be masked and
   inactive. It checks the closed link, restricts guest IPv6, then bootstraps
   or readopts an exact empty guard and verifies the link again. Stop or
   failed start leaves any installed guard in place. A restart refuses a
   malformed or populated table. The helper never brings a link UP.
5. Require an active/exited guard unit and run the helper with
   `attest /etc/portcullis/config.json`. Verify the mask, guest DOWN,
   guest-only IPv6 policy, unchanged Wi-Fi source and the second SSH
   connection through `wlan0`. Keep the unit static and the cable disconnected.

## Failure and rollback

Stop at the first failed check and keep the cable disconnected. Use the
console if management is impaired. Before undoing a successful guard
installation, use the pinned helper's `close` and `attest` operations to
prove ownership and empty sets. Stop the static unit. If and only if this
transaction created the now-attested table, delete **only**
`inet portcullis_guard`. Leave ambiguous or damaged state for console
reconciliation. Restore the saved guest IPv6 knobs with `restore-ipv6` while
the guest remains excluded and DOWN. A failed installation can leave the
stricter IPv6 values in place.

Restore the exact backed-up wired YAML, remove only the installed NM snippet
and unit, regenerate the backed-up source, and reload NM config and
connections as above. Verify the second SSH connection. This can restore
the original broad Ethernet eligibility, so maintain physical disconnection.
Remove the pilot files and unmask the stock unit only after the guard is gone
and the baseline is confirmed. Leave the stock unit disabled/inactive. If a
mask or network file changed outside this transaction, preserve the evidence
and reconcile it from the console. Never flush the ruleset.

## Physical acceptance after this stage

This procedure checks the closed, cable-disconnected install. A connected
pilot separately needs an isolated uplink peer, guest IPv4/DHCP, portal and
DNS, and physical ingress/egress, IPv6 and non-IP packet tests. Prove USB
re-enumeration, nftables lifecycle, fault recovery and independent rollback
before considering unattended connected boot. The static unit has no boot
or hotplug trigger. A post-enumeration check is not an early packet barrier.

[V3 privileged host audit](https://drive.google.com/file/d/1qQ63U711djpSzAeJaGs-UUdlv-zccp5p/view)
