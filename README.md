# Portcullis

An independent, open-source Linux captive-portal gateway for self-hosted guest access. This repository is at **Phase 1 foundation**, not a functioning gateway.

## Status

Implemented: a small, standard-library-only Go package that issues, validates, expires, and revokes in-memory lease records (maximum 15 minutes), with deterministic unit tests.

**Not implemented:** captive portal, verified client identity, packet enforcement, DHCP/DNS, nftables integration, persistent configuration, dashboard, and payment processing. In-memory lease records do not grant Internet access. Nothing here should be deployed to protect a network.

## Build and test

Requires Go 1.23 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
```

## Architecture and development

See [docs/architecture.md](docs/architecture.md) and [docs/validation.md](docs/validation.md).

Reference hardware (not yet configured): Hephaestus (Ubuntu/N100) and a GL.iNet Slate AP, with a UniFi switch carrying a proposed isolated VLAN. Network configuration and management access are unverified. No scripts in this repository modify host networking.

## Licensing

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
