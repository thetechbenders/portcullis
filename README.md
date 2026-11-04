# Portcullis

Self-hosted, open-source Linux captive-portal gateway project. **Not a deployable guest gateway.**

## Status

**Phase 1 merged:** bounded, volatile 15-minute Go lease decision records, including concurrency tests.

**Phase 2 PR (ready for review):** nftables policy text rendering, an explicit **bootstrap** batch for use only when guest networking is not exposed, a separate **in-place reconciliation** batch for pre-existing hooked base chains, and an isolated four-namespace packet lab. The standard policy CLI never executes nftables.

The lab checks IPv4/IPv6 guest INPUT and bidirectional FORWARD filtering, per-rule drop counters, one-way UDP probes and deliberate broken-rule mutations. It also exercises kernel timeout sets, existing TCP revocation/recovery, established UDP **inbound** revocation/expiry/recovery, and a bounded UDP flood during repeated in-place reconciliation. All test-only source-IP grants remain in the `netnslab` build-tagged binary and test table.

**Warning:** full-table bootstrap/replacement can leak packets across base-chain hook generation changes, even though its resulting state and rollback semantics are atomic. **Never apply the bootstrap to an active guest interface or use it for live reconciliation.** The in-place reconciler maintains existing base-chain hooks, but lab stress results do not prove gap freedom for every kernel, topology, or hardware offload path.

**Not implemented:** production firewall installer and boot/reload ownership, verified network identity, bridge/flowtable/tc/XDP checks, trusted grant lifecycle, conntrack cleanup, privileged controller and IPC, captive portal, DHCP/DNS, UI, payment system or physical network integration.

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
