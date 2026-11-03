# Disposable Linux network namespace lab

Four isolated namespaces simulate a guest, gateway, upstream endpoint and protected LAN using veth devices and private routes. The script loads nftables policies only inside the disposable gateway namespace. It requires root and is intended **only for a GitHub-hosted ephemeral runner or disposable VM**, never a live gateway.

## Build

```sh
go build -o /tmp/portcullis-policy ./cmd/portcullis-policy
go build -tags netnslab -o /tmp/portcullis-lab-policy ./tests/netns/policy
go test -tags netnslab ./internal/enforce
sudo bash tests/netns/run.sh /tmp/portcullis-policy /tmp/portcullis-lab-policy
```

Dependencies: Go 1.26+, nftables, iproute2, iputils-ping, Python 3, root and Linux network namespaces. Hosted CI uses `ubuntu-24.04` with a ten-minute job limit.

## Evidence produced

- Before installing a firewall, prove guest-to-gateway and guest-to-WAN/LAN IPv4/IPv6 routing, plus WAN/LAN-to-guest routing.
- Pin IPv6 gateway neighbor mapping so loss of neighbor discovery cannot masquerade as a successful FORWARD denial.
- Apply the baseline, then confirm IPv4/IPv6 guest INPUT and guest FORWARD in **both directions** reach the correct nft drop counter.
- Apply the same baseline a second time; assert no duplicate rules. Insert intentionally unsafe broad permits *only inside the lab*, prove they bypass the current rules, then atomically reapply the baseline and assert the permit is gone in both directions.
- Submit an invalid batch and verify the existing deny remains effective.
- Replace the disposable lab table in a single nft transaction with a build-tagged source-IP timeout-set fixture. Prove its empty set starts closed, controlled guest-to-WAN grants work and unrelated/reverse/IPv6 paths remain denied.
- Revoke a grant during an existing TCP exchange, verify a receive timeout, server liveness, no second payload receipt and correct drop counter, and prove recovery of the same socket when a test grant returns.
- Verify a separate short kernel set timeout denies new packets after expiry.

All operations occur in temporary namespaces, with trap cleanup and diagnostics on errors.

## Limitations

The intentionally unsafe test grant is not trusted client identity. This lab does not test physical bridging, AP management, flowtables, boot persistence, conntrack cleanup, production nftables ownership, DHCP/DNS, or the captive portal. A demo table replacement transaction is not authority to install any rule on a non-disposable host.
