# Portcullis

An independent, open-source Linux captive-portal gateway for self-hosted guest access. This repository is **not yet a deployable gateway**.

## Status

**Phase 1 merged:** a standard-library Go package for bounded, volatile guest lease decision records (maximum fifteen minutes, one active record per client label, maximum 1,024 records), with unit and concurrency tests.

**Phase 2 draft PR:** an inert Go nftables deny-baseline renderer, plus a disposable four-namespace Linux integration laboratory and an explicitly unsafe test-only timed IPv4 allow-set fixture. The CI lab validates default-deny IPv4/IPv6 packet paths, protected LAN isolation, test grants, kernel expiration, and revocation of an established TCP exchange. See [Phase 2 notes](docs/phase2.md) and [lab documentation](tests/netns/README.md).

**Not implemented:** verified network client identity, captive portal, production nftables controller, boot-persistent baseline, secure allow-set IPC, DHCP/DNS, trusted deployment, persistent configuration, dashboard, and payments. Lease IDs are bearer secrets, not proof of network identity. **Do not install the fixture rules on a real guest network.**

## Build and test

Requires Go 1.26 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
test -z "$(gofmt -l .)"
```

The optional namespace integration test requires an isolated disposable Linux VM/runner with root, nftables, iproute2, iputils-ping, and Python 3. It is run automatically in pull-request CI. See the lab documentation before attempting to execute it manually.

## Architecture and development

See [docs/architecture.md](docs/architecture.md), [docs/validation.md](docs/validation.md), [docs/phase2.md](docs/phase2.md), and [tests/netns/README.md](tests/netns/README.md). The intended deployment uses a Linux mini-PC, managed VLAN-capable switch, and guest access point, subject to site-specific inventory and recovery testing. Only the explicitly invoked disposable integration harness creates network namespaces.

## Licensing

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
