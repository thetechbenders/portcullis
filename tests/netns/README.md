# Network namespace integration laboratory

This is a **disposable, root-required Linux integration test**. Run it only on an ephemeral GitHub Actions runner or disposable VM. It creates and deletes four Linux network namespaces, veth pairs, private routes, local nftables state, and gateway forwarding sysctls confined to the gateway namespace. It does not attach any physical NIC or change the home's live LAN. It does require privileges on the test host, so it must never be run casually on Hephaestus.

## Test topology

```text
guest ns (10.203.0.2, 2001:db8:203::2)
     |
   guest0
gateway ns (guest0 + uplink0 + lan0)
      |                         |
   uplink0                     lan0
      |                         |
WAN ns (198.18.0.2)       protected LAN ns (10.204.0.2)
```

The WAN address belongs to the reserved IPv4 benchmarking range. IPv6 uses documentation prefixes. Routes exist only inside the four namespaces.

## Execution

Prerequisites: Go 1.26+, iproute2, nftables, iputils-ping, Python 3, root privileges and Linux network namespaces.

```sh
go build -o /tmp/portcullis-policy ./cmd/portcullis-policy
sudo bash tests/netns/run.sh /tmp/portcullis-policy
```

The test requires pre-policy packet connectivity to pass before asserting denials. It checks `nft -c -f` and then loads the rule in the gateway namespace. On exit (success or failure), the script deletes the temporary namespaces, processes, and files.

### Two different policies

1. The **deny-only baseline** renders no allows. It must reject guest INPUT and guest FORWARD for IPv4 and IPv6 while leaving unrelated WAN ingress unaffected.
2. The **unsafe fixture policy** adds an initially empty kernel set and accepts only IPv4 traffic from a test source address on the fixture uplink. It is **not a production security design**: source IP alone is spoofable. It is used only to test the set timeout and packet filtering mechanics. Explicit deletion must terminate an already established TCP application exchange; expiry must stop new packets after the kernel timeout. Protected LAN, host INPUT and IPv6 remain denied.

There is intentionally no real captive portal, client identity binding, persistent host boot rules, verified DHCP ownership, privileged IPC, or conntrack cleanup here. An established TCP exchange failing after revocation is **not** evidence that stale conntrack entries have been deleted: that remains a future gate.

The fixture transitions between deny-only and timed-test policies with a table deletion and recreation inside its disposable namespace. This gap is prohibited in a real deployment. Real policy changes must be atomic, remain default-deny, and avoid changing the persistent baseline.

## CI

The `netns` job runs on a disposable GitHub-hosted Ubuntu runner and installs its CLI prerequisites. Do not port this job to a self-hosted runner without explicit network-isolation review.

## Not yet established

- Production packet-path authorization, identity binding, anti-spoofing enforcement, client reassignment and AP management isolation
- Persistent boot-time deny across power loss, firewall reload or service crash
- Real nftables controller with atomic allow-set updates and strict API validation
- Conntrack cleanup (distinct from immediately blocking established packets)
- Real VLAN, switch, AP, DHCP/DNS or captive portal behaviors
