# Disposable Linux network namespace lab

Four isolated namespaces simulate a guest, a gateway, an upstream endpoint, and a protected LAN using only virtual Ethernet devices and private routes. The script loads nftables rules only in the disposable gateway namespace. It requires root and is intended **only for an ephemeral hosted CI runner or disposable VM**, never Hephaestus or any production host.

## Build

```sh
go build -o /tmp/portcullis-policy ./cmd/portcullis-policy
go build -tags netnslab -o /tmp/portcullis-lab-policy ./tests/netns/policy
go test -tags netnslab ./internal/enforce
sudo bash tests/netns/run.sh /tmp/portcullis-policy /tmp/portcullis-lab-policy
```

Dependencies: Go 1.26+, nftables, iproute2, iputils-ping, Python 3, root and Linux network namespaces. The GitHub Actions job executes the test on `ubuntu-24.04` with a ten-minute job timeout.

## Tests and evidence

- Pre-policy positive controls for guest-to-gateway IPv4/IPv6 INPUT and guest-to-upstream/protected-LAN forwarding.
- IPv6 gateway neighbor entry pinned so INPUT filtering cannot inadvertently prevent test packets from reaching the FORWARD hook.
- The baseline policy must deny guest IPv4/IPv6 INPUT and FORWARD, with an increase in the specific nftables drop counter for each blocked test.
- The lab-only policy starts with an empty kernel timeout set and authorizes a source-IP test fixture on the isolated WAN path, while guest INPUT, guest-to-LAN and IPv6 remain denied.
- A TCP connection must first exchange a successful application acknowledgement. Following a set-element deletion, the second message times out, the server must remain alive, the second message must not have been received, and the correct FORWARD drop counter must increase. After restoring the grant, the **same socket** must complete the exchange.
- A separate short-lived grant expires under kernel set timeouts; attempted forwarding afterwards is denied.

The namespace harness installs two different policies by submitting a single nft transaction deleting the previous lab table and declaring the next. This is a test-only transition, not a production rule-management implementation. Rules are not installed on the host network. The cleanup trap removes all temporary namespaces/processes and prints diagnostic interface/ruleset information on failures.

## Unverified properties

Reverse direction (LAN/WAN-to-guest), spoofing resistance, bridge and flowtable bypass, production rule idempotency, actual conntrack deletion, service crash/reboot persistence, DHCP/DNS, captive portal, real hardware and client identity all remain unimplemented or untested. No application-level fixture grant is safe to reuse in production.
