# Portcullis

An independent, open-source Linux captive-portal gateway for self-hosted guest access. This repository is **not yet a functioning gateway**.

## Status

**Phase 1:** a standard-library Go package for bounded, volatile guest lease decision records (up to fifteen minutes, one active record per client label, maximum 1,024 records), with unit and concurrency tests.

**Phase 2 (in development):** a pure Go renderer for a default-deny nftables baseline. It only emits text and **does not install rules**. It denies all guest INPUT/FORWARD traffic and does not support guest authorization yet. See [Phase 2 notes](docs/phase2.md).

**Not implemented:** verified network client identity, captive portal, packet enforcement integration, DHCP/DNS, nftables installation, persistent configuration, dashboard, and payments. The lease ID is a bearer secret, not authorization to route packets. Nothing here should be deployed to protect a network.

## Build and test

Requires Go 1.26 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
test -z "$(gofmt -l .)"
```

## Architecture and development

See [docs/architecture.md](docs/architecture.md), [docs/validation.md](docs/validation.md) and [docs/phase2.md](docs/phase2.md). The intended deployment uses a Linux mini-PC, managed VLAN-capable switch, and guest access point, subject to site-specific inventory and recovery testing. No scripts in this repository modify host networking.

## Licensing

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
