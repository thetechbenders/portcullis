# Portcullis

Self-hosted, open-source Linux captive-portal gateway project. **Not a deployable guest gateway.**

## Status

**Phase 1 merged:** bounded, volatile 15-minute Go lease decision records, including concurrency tests.

**Phase 2 PR (ready for review):** nftables policy text rendering, an explicit **bootstrap** batch for use only when guest networking is not exposed, a separate **in-place reconciliation** batch for pre-existing hooked base chains, and an isolated four-namespace packet lab. The standard policy CLI never executes nftables.

The lab checks IPv4/IPv6 guest INPUT and bidirectional FORWARD filtering, per-rule drop counters, one-way UDP probes and deliberate broken-rule mutations. It also exercises kernel timeout sets, existing TCP revocation/recovery, established UDP **inbound** revocation/expiry/recovery, and a bounded UDP flood during repeated in-place reconciliation. All test-only source-IP grants remain in the `netnslab` build-tagged binary and test table.

**Warning:** full-table bootstrap/replacement can leak packets across base-chain hook generation changes, even though its resulting state and rollback semantics are atomic. **Never apply the bootstrap to an active guest interface or use it for live reconciliation.** The in-place reconciler maintains existing base-chain hooks, but lab stress results do not prove gap freedom for every kernel, topology, or hardware offload path.

**Not implemented:** production firewall installer and boot/reload ownership, verified network identity, bridge/flowtable/tc/XDP checks, trusted grant lifecycle, conntrack cleanup, privileged controller and IPC, captive portal, DHCP/DNS, UI, payment system or physical network integration.

## Formnext vertical slice (in progress, uncommitted branch work)

A disposable-namespace demonstration of the whole guest journey is being built on top of the Phase 3 attestor. See [docs/formnext-design.md](docs/formnext-design.md) for the contract and trust boundaries, and [docs/formnext-demo.md](docs/formnext-demo.md) for the booth runbook.

- `portcullisd` (privileged): installs the persistent guard only while the guest link is down; attests it, bypass paths and topology before serving; built-in DHCPv4 server as the identity source; timed kernel grant elements; revoke-all on start; degraded fail-closed mode with optional guest link-down.
- `portcullis-portal` (unprivileged): guest HTTP portal and static non-recursive DNS on the gateway guest address only. It passes each guest TCP socket to the controller, which derives identity from the kernel, never from the browser.
- `portcullisctl`: operator snapshot, revoke and reset over a root-only socket, plus a loopback dashboard.
- `demo/portcullis-lab.sh`: interactive namespace lab for the show (refuses to run on hephaestus).

**Demo trust limit:** identity is (guest interface, gateway-issued DHCP address, Ethernet address), enforced by kernel `ip saddr . ether saddr` matching. A station that clones another guest's MAC *and* IP on the same segment shares that guest's access; the access layer must bind stations (WPA2/3 with client isolation).

## Checks

Go 1.26 or newer:

```sh
go test ./...
go test -race ./...
go vet ./...
go vet -tags netnslab ./...
test -z "$(gofmt -l .)"
```

Disposable GitHub Actions runners additionally build the policy commands and run root-required nftables packet tests. See [tests/netns/README.md](tests/netns/README.md), [docs/phase2.md](docs/phase2.md) and [docs/validation.md](docs/validation.md).

## Licensing

AGPL-3.0. See [LICENSE](LICENSE).
