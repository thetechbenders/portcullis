# Portcullis

An independent, open-source Linux captive-portal gateway for self-hosted guest access. This repository is **not yet a deployable gateway**.

## Status

**Phase 1 merged:** bounded, volatile Go lease records (maximum fifteen minutes, one active record per client label, maximum 1,024 records) with unit and concurrency tests.

**Phase 2 in draft review:** an inert Go nftables guest ingress deny-baseline renderer, and a disposable four-namespace Linux integration lab. The lab has its own build-tagged `netnslab` policy generator that allows source-IP-based timed grants **only for test fixtures**. No unsafe grant option is available in the normal `portcullis-policy` binary.

Hosted Linux CI has demonstrated syntax/load of the generated rules, IPv4/IPv6 guest INPUT and FORWARD drops with matching nftables counters, guest-to-protected-LAN denial, test grants, kernel expiry, and interrupting an existing TCP exchange with successful recovery on the same socket after restoring a test grant.

**Not implemented:** trusted identity, production firewall/controller, idempotent deployment transactions, boot persistence, **reverse-direction guest isolation**, conntrack cleanup, captive portal, DHCP/DNS, dashboard and payment processing. Ingress-only filtering is not complete network isolation. Do not deploy the generated rule fragments as a production gateway.

## Build and test

Requires Go 1.26 or newer.

```sh
go test ./...
go test -race ./...
go vet ./...
test -z "$(gofmt -l .)"
```

The privileged network lab is run only on disposable GitHub-hosted runners. See [tests/netns/README.md](tests/netns/README.md) before attempting it in an isolated disposable VM.

## Architecture

See [docs/architecture.md](docs/architecture.md), [docs/phase2.md](docs/phase2.md), and [docs/validation.md](docs/validation.md). Intended hardware is a dedicated Linux gateway, VLAN-capable switch and guest access point. None has been configured by this project.

## Licensing

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
