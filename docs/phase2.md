# Phase 2: persistent deny baseline (first slice)

## Status

The `internal/enforce` Go package renders a deliberately restrictive nftables **inet** ruleset fragment from a validated guest interface name. No commands run and no system state is modified. The fragment drops ALL packets from the named interface on **INPUT** and **FORWARD**, for IPv4 and IPv6, including packets in established conntrack flows. It does not yet support client authorization, DHCP, DNS or a captive portal. Do not install it on a production network.

The generated table is named `portcullis_guard`; the two filter base chains have priority `-50`. Their default policy is `accept` solely to avoid changing traffic from other interfaces. The guest ingress match takes precedence for guest traffic. The fragment is independent of any future privileged daemon and contains no owner lifetime flag.

**Operational warning:** nftables rules depend on netfilter hook ordering. No host firewall inspection, nft parser verification, namespace packet test or production deployment has happened yet. Rendering a string is not proof of enforcement or of compatibility with the existing firewall.

## Security and extension constraints

1. Before enabling a guest VLAN, install and verify a persistent boot-time default-deny policy. Preserve existing firewall rules and management connectivity. Verify that no permitted traffic path can bypass the gateway.
2. Do not try to add a separate permissive base chain or blindly insert an `accept` into another table to authorize a client. A drop in the guest baseline is terminal. Future authorized and preauthorized exceptions must be safely integrated **ahead of the final guest drop in these chains**, with review of all other rules/hook priorities.
3. Separate the unprivileged HTTP service from a narrowly authenticated privileged controller. The guest browser must never call a raw nftables command endpoint.
4. Do not authorize packets using a browser-reported MAC/IP or bearer ID alone. Source binding needs independently observed interface, address and attachment evidence, with reassignment and spoofing tests.
5. Use bounded kernel set timeouts at or below the remaining lease lifetime. Authorization on forwarded traffic must be checked on every packet before broad established-connection allowances. Revoke affected conntrack state on logout/expiry and verify loss of existing TCP/UDP flows.
6. Keep guest IPv6 denied for MVP, including link-local access to host management. IPv6 policy and AP-local bridge/client isolation require separate tests.
7. Consider the process missing or failed whenever desired policy cannot be safely reconciled. Do not install permits on error, and do not delete the baseline deny as part of process cleanup.

## Next verification gates

- Execute `go test ./...`, `go test -race ./...`, `go vet ./...`, and `gofmt` in CI.
- Validate generated rules with `nft -c -f` in a disposable Linux namespace, never against a live ruleset.
- Implement netns guest, gateway, protected-LAN and upstream fixtures with packet-level IPv4/IPv6 tests.
- Add atomic allow-set and kernel timeout handling only after the identity contract, existing-rules integration and revocation semantics are reviewed.
- No live Hephaestus, UniFi or Slate modification until the previously documented privilege, management and recovery gates pass.
