# Formnext demo runbook

**Disposable demo machine or VM only.** The lab creates network namespaces,
veth pairs, a bridge and a dummy interface *inside* those namespaces. It never
touches a physical interface, the host firewall, Hephaestus, UniFi or GL.iNet
equipment. `demo/portcullis-lab.sh` refuses to run on `hephaestus`.

## Requirements

Ubuntu 24.04 (or newer) with root, Go 1.26+, `nftables`, `iproute2`, `conntrack`,
`busybox` (for `udhcpc`), `util-linux` (`setpriv`), Python 3.12+ and a desktop browser
(Chromium or Firefox resolve `*.localhost` to loopback).

```sh
go build -o /tmp/pc-bin/ ./cmd/portcullisd ./cmd/portcullis-portal ./cmd/portcullisctl
sudo demo/portcullis-lab.sh up /tmp/pc-bin
```

The launcher prints three URLs:

| URL | What it shows |
|---|---|
| `http://portal.localhost/` | The portal **as guest A sees it**. Host loopback port 80 preserves the HTTP Host and Origin accepted by the real portal. A relay originates the upstream connection inside guest A's namespace, so the kernel filters it as guest A's traffic. The disposable host's port 80 must be available. |
| `http://127.0.0.1:9081/` | The demo destination **through guest A**. It loads only while guest A holds a kernel grant; otherwise the relay reports only that its upstream connection failed. Confirm actual firewall denial separately using nftables counters. |
| `http://127.0.0.1:8788/` | The operator dashboard (loopback only; paste the token from `/run/portcullis-demo/operator.token`). |

## Script (about four minutes)

1. **Denied by default.** Open the destination tab: blocked. In the dashboard, the
   `guest-egress` counter rises. Guest A is recognized (DHCP binding) but has no grant.
2. **Portal reachable before authorization.** Open the portal tab. It shows the guest's
   address and device hint. These come from the gateway's own DHCP binding and the
   kernel socket, not from the browser.
3. **Request access.** Choose a duration and request access. The UI says *granted* only
   after the controller reads the grant back from the kernel. The countdown shows
   kernel-reported remaining time.
4. **Authorized traffic.** Reload the destination tab: it loads. The dashboard shows the
   grant with desired and kernel remaining time side by side, and `grant-egress` counting.
5. **Others stay out.** `sudo demo/portcullis-lab.sh status` shows guest B bound but not
   granted. The protected LAN and the "home network" behind the uplink remain dropped
   (`guest-protected`).
6. **Revoke.** Click *Revoke* in the dashboard (or `portcullis-lab.sh revoke`). The
   destination stops loading at once, existing connections included. The portal shows
   the revocation cooldown, and a new request is refused until `reset`.
7. **Kernel expiry.** Grant 30–60 s, then `portcullis-lab.sh crash` (SIGKILL the
   controller). The page keeps loading until the kernel timeout, then stops with no
   userspace involvement. The portal reports the controller as unreachable and offers
   no access.
8. **Restart is fail-closed.** `portcullis-lab.sh restart`. Any grant still alive is
   revoked on start; the guest must request again.
9. **Reset for the next visitor.** `portcullis-lab.sh reset` (or *Reset* in the
   dashboard). `portcullis-lab.sh down` removes everything.

## What to say about limitations

- Identity is the gateway-issued DHCP binding (interface, IPv4, MAC), enforced by
  kernel `ip saddr . ether saddr` matching and corroborated with the gateway's
  neighbour table and the kernel socket of the portal connection. A device that clones
  **both** another guest's MAC and IP on the same segment would share that guest's
  access. Production requires an access layer that binds stations (WPA2/3 per-station
  keys with client isolation). The lab models client isolation with isolated bridge
  ports.
- Plain HTTP portal; HTTPS is never intercepted. Captive detection relies on OS probe
  hostnames that the guest DNS points at the portal.
- No NAT, no guest IPv6 (explicitly dropped), no persistence across reboot.

## Fallback

Use the `e2e` job log from an exact-head GitHub Actions run as the offline
fallback. The automated `tests/netns/e2e.sh` suite runs only on disposable
GitHub-hosted runners, builds the real processes and fails if a prerequisite is
missing. It requires directional kernel drop counters and delivered positive
controls for packet-denial assertions. Record the successful run before the show;
a packet-test recording does not establish browser UX acceptance.

## Browser relay verification

The relay forwards bytes without rewriting Host or Origin. The portal relay
listens on host loopback port **80**, not 9080, because the portal rejects a
foreign HTTP authority. The browser must use `http://portal.localhost/` and
requests carrying the same-origin `Origin: http://portal.localhost`.
The disposable E2E job exercises those exact HTTP authorities and verifies
that a guest-bound browser relay can request a real kernel grant and reach the
uplink destination. It also tests the loopback dashboard's bearer-token gate,
kernel-backed snapshot and operator revoke through the real HTTP API. The host port 80 must be free for the demo.

A relay-generated 502/504 is *not* an enforcement verdict. Confirm packet
denial using kernel counters, controller state, and positive connectivity
controls. Manual browser/dashboard rehearsal on a disposable VM remains a
separate acceptance step; CI HTTP requests do not prove browser UX.
