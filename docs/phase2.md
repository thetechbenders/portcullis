# Phase 2: deny baseline and isolated integration lab

## Verified scope

`internal/enforce` produces nftables `inet` ruleset text for validated interface names. The production-oriented `RenderDenyBaseline` has guest INPUT and FORWARD drops for IPv4/IPv6 with no permits. The `RenderTimedFixturePolicy` exists **only to demonstrate packet filtering mechanics inside a disposable test lab**: it uses an empty kernel set and can temporarily permit fixture guest IPv4 traffic only to a fixture uplink. Source IP is forgeable and **is not an authorization identity**.

GitHub-hosted Linux namespace tests now syntax-check the generated text with `nft -c -f`, install it solely inside a disposable gateway namespace, and validate real packet behavior. They cover IPv4/IPv6 guest INPUT and FORWARD denial, protected LAN isolation, fixture timed permits, kernel timeout, and immediate blocking of an established TCP application exchange after an allow-set element is removed. See [the lab](../tests/netns/README.md).

**The project still has no production installer, privileged controller, verified identity source, conntrack cleanup, boot-persistent firewall deployment, DHCP/DNS or captive portal.** CI passing does not establish compatibility with a host's existing nftables policy or its physical network.

## Security and extension constraints

1. Install and verify a persistent default-deny INPUT/FORWARD firewall before ever enabling a guest VLAN. The baseline must survive service crash/restart and remain independent of user-space authorization management.
2. A terminal nftables drop cannot be overridden by an accept in another base chain. Any future permit belongs before the guest drop in the correct path, with atomic transitions that never expose an allow-all gap. The test fixture deletes and recreates a table **only inside its disposable namespace**. This method is forbidden in deployment.
3. Isolate unprivileged HTTP parsers from a narrowly authenticated privileged controller. Guest traffic must never reach a general-purpose nftables command API.
4. Bind network clients to trusted attachment observations, not a browser-supplied IP/MAC or a lease bearer ID. Prevent spoofing and reassignment races. The source-IP-only fixture is deliberately unfit for production.
5. Use bounded kernel allow-set timeouts no longer than the remaining valid lease duration; check guest authorization on every forwarded packet, including established flows. For logout/expiry also remove associated conntrack state. The current tests prove traffic is blocked, **not that conntrack entries are deleted**.
6. IPv6 remains denied for MVP, including host link-local access. Isolate AP-local bridging, inter-client and AP-management paths independently of gateway routing.
7. Controller failures, transaction failures, clock jumps, suspend/resume and reboot must never restore expired grants or remove the persistent deny. No automatic fail-open fallback.

## Next verification gates

- Design trustworthy client attachment observation and bounded identity/lease mapping, with tests against address reassignment and spoofing.
- Build a privileged controller with atomic nftables transactions and a narrow authenticated IPC, without permitting the guest portal to manipulate arbitrary rules.
- Prove persistence across daemon failure and reboot, reliable expiry and actual conntrack teardown, and robustness against rollback or partial application.
- Add pre-auth DHCP/DNS/portal access only after kernel enforcement remains fail-closed through adversarial testing.
- Inspect the existing Hephaestus/UniFi/Slate configuration and recovery path before considering any physical integration. No production changes are authorized.
