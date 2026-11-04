# Portcullis

An independent, open-source Linux captive-portal gateway for self-hosted guest access. This repository is **not yet a deployable gateway**.

## Status

**Phase 1 merged:** bounded, volatile Go lease records (maximum fifteen minutes, one active record per client label, maximum 1,024 records) with unit and concurrency tests.

**Phase 2 draft PR:** a pure Go generator for a guest firewall deny baseline and a disposable four-namespace Linux packet-testing lab. The policy now filters forwarded traffic in **both directions** and emits a convergent nftables table-replacement batch, but base-chain replacement has an observed packet-straddle window and is NOT safe as a live reconciler. The lab verifies removal of injected stale permits, rejects a deliberately invalid transaction without losing the active deny, and tests IPv4/IPv6 ingress, egress, test grants, kernel expiry, and established TCP revocation. Its unsafe source-IP authorization fixture is confined to a separately built `netnslab` binary and table.

**Not implemented:** production firewall installation or ownership; host-to-guest OUTPUT policy; trusted network identity; reload/boot persistence; flowtable/bridge bypass detection; conntrack cleanup; privileged controller and IPC; captive portal; DHCP/DNS; dashboard; payments.

The baseline generator emits nftables text only. It is not a safe deployment tool. Do not run these policies against a live guest network.

## Build and test

Requires Go 1.26 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
test -z "$(gofmt -l .)"
```

Packet tests are run only on disposable GitHub-hosted runners. See [tests/netns/README.md](tests/netns/README.md).

## Architecture

See [docs/architecture.md](docs/architecture.md), [docs/phase2.md](docs/phase2.md), and [docs/validation.md](docs/validation.md). Intended hardware includes a Linux gateway, VLAN-capable switch, and guest AP. No real networking has been configured.

## Licensing

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
