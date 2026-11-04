# Formnext integration evidence

## Preservation and history

The complete incoming worktree (including ignored local settings) and all Git refs
were backed up locally before any merge or edit. Archive SHA256:
`7c19a23b132341f1ca82d9e2ce8830311974593add18d1cef54b78bafd478ec1`.
Backup directory: sibling `portcullis-backup-20261104T223728Z` (private, not published).
`.claude/settings.local.json` remains ignored and untracked.

The integration branch starts at Phase 3 `669f2f6` and merges the unchanged
portal-preview commit `fd4865c`. PR #3 and PR #7 retain their original branches,
commits and draft status. No shared history was rewritten.

## Review of security boundaries

| Boundary | Code reviewed and acceptance limit |
| --- | --- |
| DHCP / identity | Bind before ACK, address reassignment removes prior authority; DHCP chaddr is a claim, corroborated by neighbour state. Payload spoofing and pool starvation remain denial-of-service risks. |
| MAC/IP | Guard requires the timed IPv4/MAC tuple. Cloning both values on shared L2 remains indistinguishable and requires station binding at the access layer. |
| Passed socket | SO_PEERCRED before read; exactly one established AF_INET TCP descriptor; exact local portal endpoint, valid peer, matching SO_NETNS_COOKIE; received descriptors are closed. |
| Guard | Exact ordered rules, hooks, priority, policy, sets and dormant-state verification; whole-ruleset scan rejects flowtables, ingress/egress chains and dup/fwd. |
| Transactions | Both grant directions use one nft batch; deletion is idempotent; success requires readback. Runtime changes only set elements, never base chains. |
| Conntrack | Original source and destination cleanup both attempted; failures are visible in events. Packet enforcement remains dependent on timed sets, not conntrack deletion. |
| Restart / degraded | Start flushes inherited grants before sockets; reconcile removes stray authority; failures enter terminal degraded mode and configured link-down failsafe. Crash leaves existing grants until their kernel timeout. |
| IPC | Root-owned runtime directory, root-only operator socket, peer-UID gated guest socket; no browser-provided identity. Guest socket mode 0666 relies on credential validation. |
| MPTCP | Portal explicitly disables MPTCP; descriptor validation requires IPPROTO_TCP. |
| HTTP | Allowed Host plus exact Origin, JSON/custom header and fetch metadata on mutation; strict bounded bodies; security headers; separate loopback operator service. Plain HTTP remains demo scope. |
| DNS | Static zone only, no recursion, REFUSED outside zone, AAAA NODATA, bounded response and rate limits. |
| Topology | Guest must be unenslaved, not bridge/bond/team, IPv6 disabled; XDP refused on guest/uplink. Added namespace-wide upper-device detection for VLAN/macvlan/ipvlan. External tc/payload rewriting by root is outside attestation. |
| Launcher | Namespace-created veth/bridge/dummy only; protected-host refusal; fixed portal readiness ownership. No production deployment acceptance. |

This is a source review, not independent security approval. The privileged
controller and local root configuration are trusted. Periodic attestation is a
snapshot; it cannot prevent a concurrent privileged actor changing topology or
packet processing. Do not deploy or merge security changes solely because CI passes.

## Local verification

Freshly executed on 2026-11-04 using the existing Go 1.26 toolchain:

- `go test -count=1 ./...` (incoming implementation, then topology correction).
- `go build ./...`.
- `go vet ./...` and `go vet -tags netnslab ./...`.
- `go test -tags netnslab ./internal/enforce`.
- `gofmt` and `git diff --check`.
- Bash syntax for both namespace suites and the demo; sh syntax for DHCP hook;
  Python compilation for lab fixtures and browser relay.

Race testing and both root namespace suites run on disposable GitHub-hosted
Ubuntu 24.04 runners. Neither root suite is run on Hephaestus. Missing prerequisites
are failures. Exact-head run links and results are recorded after CI completes.

## New experimental gates

`tests/netns/e2e.sh` uses the real daemon, unprivileged portal, DHCP client and
operator CLI. It tests initial denial, portal/DNS reachability, bounded grant,
authorized delivery, second-guest isolation, protected networks, spoofing,
explicit revoke, kernel-only expiry after SIGKILL, restart stale-grant removal,
default deny after crash, IPv6 guard behavior, wrong hook, dormant table, absent
chain and VLAN/macvlan/ipvlan mutations. A persistent bidirectional UDP fixture
requires delivery before revocation/expiry/restart and recovery on the same
sockets after a new grant; negative observations require directional drop counters.
The Phase 2 suite separately exercises existing TCP streams and repeated
in-place reconciliation. All routes used for negative probes have delivered
positive controls before guard installation.

## Remaining demo work

- Independent adversarial review of the privileged controller and grant boundary.
- Operator rehearsal of browser relay/dashboard and complete demo teardown on a
  disposable demo VM; automated packet CI does not establish browser UX acceptance.
- Access-layer station binding before any shared-segment production use.
- Keep NAT, HTTPS, physical deployment and infrastructure changes out of this slice.
