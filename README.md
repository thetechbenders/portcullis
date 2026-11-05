# Portcullis

Self-hosted, open-source Linux captive-portal gateway project. **Not a deployable guest gateway.**

## Status

**Phase 1 merged:** bounded, volatile 15-minute Go lease decision records, including concurrency tests.

**Phase 2 merged:** nftables policy text rendering, an explicit **bootstrap** batch for use only when guest networking is not exposed, a separate **in-place reconciliation** batch for pre-existing hooked base chains, and an isolated four-namespace packet lab. The standard policy CLI never executes nftables.

The lab checks IPv4/IPv6 guest INPUT and bidirectional FORWARD filtering, per-rule drop counters, one-way UDP probes and deliberate broken-rule mutations. It also exercises kernel timeout sets, existing TCP revocation/recovery, established UDP **inbound** revocation/expiry/recovery, and a bounded UDP flood during repeated in-place reconciliation. All test-only source-IP grants remain in the `netnslab` build-tagged binary and test table.

**Warning:** full-table bootstrap/replacement can leak packets across base-chain hook generation changes, even though its resulting state and rollback semantics are atomic. **Never apply the bootstrap to an active guest interface or use it for live reconciliation.** The in-place reconciler maintains existing base-chain hooks, but lab stress results do not prove gap freedom for every kernel, topology, or hardware offload path.

**Production gaps:** boot/reload ownership, access-layer station binding, tc/payload-rewriting attestation, HTTPS, payment and physical network acceptance. The Formnext draft below implements a disposable demonstration; it is not approved for deployment.

## Formnext vertical slice (integrated draft)

A disposable-namespace demonstration of the whole guest journey is integrated on top of the Phase 3 attestor. [Integration evidence and review limits](docs/formnext-integration.md) track the original handoff, security corrections and exact-head CI. [PR #8](https://github.com/thetechbenders/portcullis/pull/8) remains draft and unmerged pending review. See [docs/formnext-design.md](docs/formnext-design.md) for the contract and trust boundaries, and [docs/formnext-demo.md](docs/formnext-demo.md) for the booth runbook.

- `portcullisd` (privileged): installs the persistent guard only while the guest link is down; attests it, bypass paths and topology before serving; built-in DHCPv4 server as the identity source; timed kernel grant elements; revoke-all on start; degraded mode with **mandatory guest-link isolation** before grant cleanup.
- `portcullis-portal` (unprivileged): guest HTTP portal and static non-recursive DNS on the gateway guest address only. It passes each guest TCP socket to the controller, which derives identity from the kernel, never from the browser.
- `portcullisctl`: operator snapshot, revoke and reset over a root-only socket, plus a loopback dashboard.
- `demo/portcullis-lab.sh`: interactive namespace lab for the show (refuses to run on hephaestus).

**Required failsafe setting:** `failsafe_link_down: true`. The gateway refuses configurations that disable or omit this field, and the controller refuses to construct without an isolation dependency. If guard attestation fails, it attempts to bring the guest interface administratively down *before* removing authorization. The controller reads the link state back after `ip link set down`, retries isolation on each degraded reconciliation tick (including after success), and reports **confirmed** versus **unconfirmed** isolation in the operator snapshot. Confirmation is a point-in-time observation, not a guarantee against a later privileged network mutation; degraded is not synonymous with physically isolated. The Formnext deployment remains confined to a disposable, controlled network. An independent isolation mechanism and explicit isolation-status evidence are required before production use.

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
