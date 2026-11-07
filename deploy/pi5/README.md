# Pi 5 first-silicon pilot (supervised, wired guest disconnected)

**Status: candidate installer assets and test procedure. NOT authorized for remote application, reboot, live cable connection or autonomous connected boot.** The software in this directory is for a supervised first installation after independent console recovery is demonstrated. V3 host observations are snapshots, not deployment permission.

## Purpose and boundary

This package is intended to move Portcullis beyond offline policy renderers onto the Raspberry Pi 5 **without exposing a guest network**. It supports initial binary/config installation and a one-time nft guard bootstrap with the guest cable physically disconnected. The current Go controller still requires a separately configured guest IPv4 address, protected isolated uplink and portal before the connected end-to-end trial.

It does not enable or restart services by itself. Do not enable this unit at boot until a separate cold-boot and hotplug contract has been accepted.

**Do not apply `usbcore.authorized_default=0` in this first pilot.** It affects every USB device. The separate USB policy renderer is for future independently recovered unattended testing, not the first supervised installation.

## Physical invariants

- Guest RJ45 cable is physically **disconnected**, before/during changes and rollback.
- Management: `wlan0`, independently verified SSH return route, live Wi-Fi preserved.
- Uplink: onboard `eth0`, not a default-route fallback; future test peer must be isolated.
- Guest: the fresh, independently pinned Plugable USB device. Private permanent MAC, USB parent, driver, VID:PID, ifindex and active generation are verified before each step.
- Independently demonstrated local or serial recovery and a tested, bounded rollback mechanism exist. **An SSH session or getty listing is not such recovery.**
- No other manager or cloud-init rule may raise the guest. If a device match, policy readback or management route drifts, STOP and keep the cable disconnected.
- Never install a lifecycle override that masks nftables load/stop behavior unless another verified owner restores and attests the guard at boot.

## Offline preparation (safe on a developer machine)

Build binaries from an exact reviewed commit:

```sh
go build -o ./out/portcullisd ./cmd/portcullisd
go build -o ./out/portcullis-hostprep ./cmd/portcullis-hostprep
go test -count=1 ./...
go vet ./...
python3 -m unittest discover -s deploy/pi5 -p 'test_*.py' -v
```

Create an **owner-only** private JSON identity file outside the repository:

```json
{"GuestMAC":"<verified guest permanent MAC>","UplinkMAC":"<verified onboard eth0 permanent MAC>","ManagementMAC":"<verified wlan0 permanent MAC>"}
```

The example placeholder values are not valid actual device identities. The file must have mode 0600. Never commit it, paste it into a PR, or pass its contents as command-line arguments.

```sh
./out/portcullis-hostprep -identities /PRIVATE/identities.json -out /PRIVATE/new-pilot-candidates
```

The generator creates a 0700 directory with 0600 files, refuses existing output directories, validates distinct nonmulticast role MACs, and **writes no /etc configuration**. Review the output privately. The strict NetworkManager candidate is `[keyfile] unmanaged-devices=type:ethernet;except:mac:<uplink>`; NetworkManager's device-list syntax gives the `except:` selector precedence. The Netplan fragment is **not a complete YAML replacement** and must be reconciled with the current protected source without touching the WLAN section.

## Separate supervised installation transaction (NOT executed by this PR)

Only after independent recovery/rollback is tested and a specific transaction is authorized:

1. Back up exact existing file bytes, ownership, modes and loaded states for `/etc/NetworkManager/conf.d/`, `/etc/netplan/`, relevant systemd units, and firewall inventory to a private owner-only directory. Keep an independently triggered recovery mechanism; never rely on this SSH session for rollback.
2. Confirm management connectivity and `wlan0` return route. Confirm guest physical cable disconnect and absence of guest carrier/addresses/routes. Verify physical device identities again.
3. Install the reviewed guest-deny NetworkManager snippet, preserving unrelated list semantics. Reconcile persistent Netplan Ethernet source with the MAC-scoped uplink, preserving Wi-Fi credentials and passthrough. **Do not hand-edit generated /run files**. Verify effective policy and exactly which Ethernet devices are manageable. Do not restart all networking.
4. With the guest physically disconnected, explicitly enforce guest DOWN and read it back. Verify NetworkManager reports guest unmanaged and management still uses `wlan0`; if either check fails, stop immediately.
5. Install the separately validated `portcullisd` binary, private `/etc/portcullis/config.json`, executable helpers as `/usr/local/libexec/portcullis-pilot-closed` and `/usr/local/libexec/portcullis-pilot-restrict`, and `portcullis-guard.service` as a systemd unit. Do **not** enable the unit yet.
6. Manually start the guard unit once. The preflight checks physical guest ancestry, DOWN, absent/unverified carrier, NetworkManager exclusion and exclusive `wlan0` default route. The restriction helper disables IPv6/RA on **only** the verified DOWN guest. `portcullisd bootstrap` refuses an already-existing table or UP guest. `portcullisd attest` independently checks the guard, bypass and topology. A failure authorizes **no** link UP or cable connection.
7. Keep guest DOWN and physically disconnected. Inspect nftables guard and service state. The distro `nftables.service` remains a global-flush hazard until the reviewed ownership/lifecycle candidate is applied as part of its own protected transaction. Never start/reload/stop that stock service while relying on the Portcullis guard.
8. Capture the finished state privately. A successful first pilot means **guard installed and attested on a closed guest**, not a functioning or connected captive portal.

**The service is deliberately manual-only for this first silicon test.** The unit must not be enabled or used as an automatic hotplug actor until boot ordering and independent device admission are tested.

## Rollback

Keep guest Ethernet physically disconnected throughout. Independently verify the working console/recovery path, then remove or disable only the **transaction-owned, version-matched** service installation and restore exact backed-up NetworkManager/Netplan files with original permissions and ownership. Do not issue a global `nft flush ruleset` or delete arbitrary nftables tables. Never restore the broad wired profile while guest exposure is connected. Record residual Portcullis guard state and require independent reconciliation rather than replacing a live hooked table.

For a failure after guard installation, keep guest DOWN and cable disconnected. Do not try to recover by deleting the guard or accepting an unknown preexisting table. Use the independent recovery route to restore management first.

## Physical follow-on acceptance (separate authorization)

An authorized isolated packet pilot requires known guest IPv4 configuration, independent uplink peer, functional DHCP/portal/DNS, nftables INPUT/FORWARD/OUTPUT counter tests, loss/restart fault injection, USB re-enumeration, nftables reload/service-lifecycle tests, and the tested console rollback. It requires physically connecting the guest to an isolated test peer **only after** those specific checks and an explicit go decision.

Unattended connected-boot requires a separate proven pre-driver USB authorization path or equivalently trusted exposure gate. The current pure USB admission code is not an installed privileged authorizer.

Reference: [V3 privileged host audit](https://drive.google.com/file/d/1qQ63U711djpSzAeJaGs-UUdlv-zccp5p/view).
