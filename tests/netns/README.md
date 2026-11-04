# Disposable network namespace integration tests

**Root required, disposable GitHub-hosted runner or VM only. Never run against Hephaestus or a production gateway.**

```sh
go build -o /tmp/portcullis-policy ./cmd/portcullis-policy
go build -tags netnslab -o /tmp/portcullis-lab-policy ./tests/netns/policy
sudo bash tests/netns/run.sh /tmp/portcullis-policy /tmp/portcullis-lab-policy
```

Dependencies: nftables, iproute2, iputils-ping, Python 3, Go 1.26+, Linux network namespaces. The CI `netns` job runs on a disposable Ubuntu 24.04 runner.

The lab creates only veth links in guest, gateway, protected LAN, and upstream namespaces, changes forwarding sysctls only inside the gateway namespace, and traps cleanup. Test probes are deliberately strict:

- Positive connectivity controls before firewall application
- IPv4/IPv6 and one-way UDP guest-denial assertions with direction-labelled nft counters
- Broken-interface mutations that must reveal leaks
- Separate first-install bootstrap and deny-only in-place rule reconciliation, including repeated updates
- Controlled high-rate UDP flood with a delivery counter during in-place reconciliation
- Kernel error rollback, stale-permit cleanup, timed test grants, TCP blocked delivery and recovery
- UDP flow established by the guest, then **server-to-guest** data attempted after grant deletion and kernel expiry; a drop-counter delta, receive timeout and same-socket recovery are required

The `netnslab` grant is spoofable by source IP and never represents production identity. The bootstrap batch is known to have a possible packet-straddle gap and must only be used while guest networking is physically/administratively closed. No host-global policy is modified.
