# Formnext vertical slice: design contract

Status: **implementation contract for the disposable namespace demonstration.**
Nothing here authorizes deployment on Hephaestus, UniFi, GL.iNet or any physical
interface. All kernel testing happens inside throwaway network namespaces on a
disposable runner.

## Goal

Demonstrate, with real kernel packet filtering, a guest who joins an isolated
network, is denied by default, reaches only the local portal, requests bounded
access, reaches a designated destination, and then loses access through explicit
revocation or kernel-enforced expiry, with controller crash/restart never
granting anything.

## Processes and trust boundaries

```text
guest ──(guest0)──► gateway netns ──(uplink0)──► demo destination
                    │
                    ├─ kernel guard: table inet portcullis_guard (persistent, attested)
                    ├─ portcullisd    privileged: DHCP, nft element updates, conntrack, IPC
                    ├─ portcullis-portal  unprivileged uid: guest HTTP + guest DNS
                    └─ portcullisctl  operator CLI / loopback dashboard (operator socket)
```

| Component | Privilege | Trusted for | Never trusted for |
|---|---|---|---|
| Kernel guard (nftables) | kernel | the only packet authority; expiry via set timeouts | n/a |
| `portcullisd` | root / CAP_NET_ADMIN in the gateway netns | address assignment, binding table, grant decisions, kernel element changes | anything a guest or the portal asserts |
| `portcullis-portal` | unprivileged uid | presenting real guest TCP connections, rendering UI | guest identity (it cannot name an address) |
| Browser / guest | none | nothing | identity, authorization, timing |

The browser is never an enforcement boundary. No lease ID, cookie, header, MAC or
IP supplied by the browser or by the portal is accepted as identity.

## Identity binding (demo trust model)

A guest is identified as the tuple **(guest interface, DHCP-bound IPv4 address,
DHCP-bound Ethernet address)**, established from evidence the gateway observes:

1. **Address assignment is issued by `portcullisd` itself** (built-in DHCPv4
   server bound to the guest interface with `SO_BINDTODEVICE`). The binding table
   is the controller's own record; it is not reported by a client or the portal.
2. **Kernel anti-spoofing.** Every guest packet the guard admits to the portal,
   DNS or uplink must match `ip saddr . ether saddr` against a live kernel set
   (`bound_v4` for portal/DNS, `granted_v4` for forwarding). A station that
   forges another's IPv4 address with its own MAC is dropped by the kernel.
3. **Kernel-observed connection.** The portal passes the guest's live TCP socket
   to the controller over `SCM_RIGHTS`. The controller itself calls
   `getsockname`/`getpeername`, verifies it is an established IPv4 TCP socket on
   the configured portal address, and uses the kernel peer address.
4. **Neighbour cross-check.** The kernel ARP entry for that address on the guest
   interface must be resolved and carry the DHCP-bound MAC. Disagreement is
   reported as `ambiguous` and nothing is granted.

**Residual limitation (stated, not hidden):** a station that clones *both* the
victim's MAC and IPv4 address on a shared L2 segment is indistinguishable at the
gateway. Production use requires the access layer to bind stations to MACs
(WPA2/3 per-station keys with AP client isolation, or per-port locking). In the
lab, guests sit on a bridge with isolated ports to model client isolation, and the
MAC-clone case is exercised as a documented limitation test, not a pass.

## Kernel guard (exact structure)

Installed **once while the guest interface is administratively down**
(`portcullisd bootstrap`). At runtime only set elements change; hooked base chains
are never deleted, recreated or flushed by the controller.

```nft
table inet portcullis_guard {
	set bound_v4       { type ipv4_addr . ether_addr; size 1024; flags timeout; }
	set granted_v4     { type ipv4_addr . ether_addr; size 1024; flags timeout; }
	set granted_dst_v4 { type ipv4_addr;              size 1024; flags timeout; }
	chain guest_input {
		type filter hook input priority -50; policy accept;
		iifname "<guest>" meta nfproto ipv4 udp sport 68 udp dport 67 counter accept comment "guest-dhcp"
		iifname "<guest>" ip daddr <gw> ip saddr . ether saddr @bound_v4 udp dport <dns> counter accept comment "guest-dns"
		iifname "<guest>" ip daddr <gw> ip saddr . ether saddr @bound_v4 tcp dport <portal> counter accept comment "guest-portal"
		iifname "<guest>" counter drop comment "guest-input"
	}
	chain guest_forward {
		type filter hook forward priority -50; policy accept;
		iifname "<guest>" ip daddr { <protected prefixes> } counter drop comment "guest-protected"
		iifname "<guest>" oifname "<uplink>" ip saddr . ether saddr @granted_v4 counter accept comment "grant-egress"
		iifname "<guest>" counter drop comment "guest-egress"
		iifname "<uplink>" oifname "<guest>" ip daddr @granted_dst_v4 ct direction reply ct state established,related counter accept comment "grant-ingress"
		oifname "<guest>" counter drop comment "guest-ingress"
	}
}
```

Properties:

- IPv6 from or to guests matches no accept rule and is dropped in both hooks; the
  lab additionally disables IPv6 on the guest interface.
- There is **no blanket `ct state established accept`**. Every forwarded packet is
  checked against the timed grant sets, so expiry or revocation stops existing TCP
  and UDP flows in both directions without userspace.
- Grant elements always carry a timeout of at most 15 minutes. nft accepts
  elements *without* a timeout on `flags timeout` sets (they never expire), so
  attestation reports `Timeout == 0` and the controller deletes such elements as
  hostile state.
- `drop` in any base chain is final, so other tables cannot re-admit a packet this
  guard drops. Bypass paths that skip the inet forward hook altogether (flowtables,
  netdev ingress/egress chains on the guest or uplink device, bridging the guest
  interface, XDP, or upper devices stacked on guest/uplink interfaces) are attested separately and cause the controller to fail closed.

Element updates use one `nft -f -` transaction each. Refresh/delete use the
idempotent `add … timeout 1s; delete …; add … timeout T` idiom because deleting an
absent element fails the whole batch. A grant updates `granted_v4` and
`granted_dst_v4` in the same transaction.

## Controller lifecycle and fail-closed behaviour

1. `portcullisd bootstrap`: refuses unless the guest interface is administratively
   down and the guard table is absent. Renders the guard, applies it, attests it.
2. `portcullisd run`: attests the guard and bypass checks **before** opening any
   socket. On failure it exits without serving DHCP or IPC.
3. On start it **revokes every grant** (flushes both grant sets and conntrack for
   affected guests). A restart never inherits authority. Live `bound_v4` elements
   are adopted into the DHCP table so existing clients keep their addresses and
   portal reachability.
4. Reconcile loop (bounded interval): re-attest, compare desired grants with
   kernel elements, delete stray/untimed/over-long elements, mark grants whose
   elements vanished as ended (they are **never** re-added), refresh the operator
   snapshot. Attestation failure enters `degraded`: grants are flushed when
   possible, every request is refused, and with `failsafe_link_down` the guest
   interface is set administratively down. Degraded persists until restart.
5. A crash leaves the guard and any granted elements in place; each grant still
   expires in the kernel at its timeout, at most 15 minutes after issue. No new
   authority can be created without a running controller.

Privileged command execution uses fixed absolute paths from configuration
(`nft`, `conntrack`, `ip`), structured arguments, a cleared environment, stdin
batches rendered only from validated typed values, bounded output, and context
deadlines. No shell is invoked.

## Guest grant state machine

```text
unrecognized ──DHCP ACK──► denied ──request──► granted ──expiry/kernel loss──► denied
      ▲                      ▲  │                 │
      └──lease end/RELEASE───┘  │                 ├──guest release──► denied
                                │                 └──operator revoke─► revoked ──cooldown──► denied
                                └──evidence conflict──► ambiguous (no grant)
any state ──attestation failure──► unavailable
```

- Grant length: `grant_default_seconds` unless requested; requests outside
  `[30, grant_max_seconds]` are rejected, not clamped. The kernel timeout is
  `min(requested, DHCP lease remaining)` floored to whole seconds.
- One live grant per binding; a duplicate request returns the current grant.
- Per-binding minimum interval between grant requests; operator revocation sets a
  cooldown keyed by MAC that survives DHCP renewal and reconnects.
- The guest UI shows `granted` only when the kernel elements are present, with the
  kernel-reported remaining time.
- Revocation (guest release, operator revoke, DHCP release/expiry, reassignment)
  deletes both grant elements in one transaction, then deletes conntrack entries
  for the address in both directions.

## Control protocol

Two Unix stream sockets owned by `portcullisd` (see `internal/ipc`):

- `guest_socket`: peer uid must equal `portal_uid` (checked with `SO_PEERCRED`).
  Ops `status`, `request`, `release`; exactly one `SCM_RIGHTS` descriptor (the
  guest TCP connection) is required and no request field can name a client.
- `operator_socket`: mode 0600, peer uid 0 only. Ops `snapshot`, `revoke`, `reset`;
  descriptors are rejected.

One JSON request and one JSON response per connection, each at most
`ipc.MaxMessageBytes`, with read/write deadlines and a bounded number of concurrent
connections.

## Portal

- Listens only on `gateway_v4:portal_port`; DNS only on `gateway_v4:dns_port`.
  Never a wildcard address.
- Serves the guest UI and `/api/session` (GET), `/api/access` and `/api/release`
  (POST). POSTs require `Content-Type: application/json`, an
  `X-Portcullis-Request: 1` header, an `Origin` matching the allowed portal host,
  and a Host header from the configured allow-list (DNS-rebinding defence).
- Requests for OS captive probe hosts redirect unauthorized guests to the portal
  and return the platform's expected success response for granted guests.
- HTTPS is never intercepted. Guest DNS is a static authoritative responder for the
  portal, probe and configured demo names only: no recursion, `REFUSED` otherwise,
  no AAAA data.
- The operator view is a separate loopback-only listener backed by the operator
  socket, not reachable from guests.

## Command-line contract

All binaries take `-config FILE` (schema: `internal/config`).

| Command | Privilege | Behaviour |
|---|---|---|
| `portcullisd bootstrap -config F` | root | install guard only if guest link is down and table absent; attest; exit 0 |
| `portcullisd attest -config F` | root | print attestation result; exit 0 only if guard, bypass and topology checks pass |
| `portcullisd run -config F [-ready-file P]` | root | attest, revoke all grants, adopt bindings, serve DHCP + both sockets; write `P` once serving |
| `portcullis-portal -config F [-ready-file P]` | non-root (refuses uid 0) | guest HTTP on `gateway:portal_port`, DNS on `gateway:dns_port` |
| `portcullisctl -config F snapshot` | root | operator snapshot JSON on stdout |
| `portcullisctl -config F revoke MAC` | root | operator revocation (cooldown applies) |
| `portcullisctl -config F reset` | root | revoke every grant and clear cooldowns; DHCP bindings kept |
| `portcullisctl -config F serve -listen 127.0.0.1:8788 -token-file P` | root | loopback operator dashboard; bearer token required for its API |

Exit status is non-zero on any refusal; refusals print one line to stderr.

## Out of scope for the demo

NAT/masquerade, IPv6 guest service, HTTPS portal, RFC 8910 DHCP captive-portal
option (it requires an HTTPS API), multi-AP, payment, accounts, persistence across
reboot, and any physical deployment.
