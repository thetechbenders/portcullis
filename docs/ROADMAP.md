# Portcullis roadmap

**Planning baseline:** November 5, 2026.  
**Code baseline:** \`main\` merge commit [\`ebe1aa5\`](https://github.com/thetechbenders/portcullis/commit/ebe1aa5ddb75c778b445b9bfd44384d2f0576b10).  
**Status:** Proposed roadmap of record, pending review/merge of this documentation change. No milestone or issue authorizes deployment, hardware changes, a release or a code merge.

Portcullis is a security-first, self-hosted Linux guest authorization gateway. Its currently integrated implementation is a **disposable Formnext 2026 network-namespace demonstration**, not a ready-to-install hotspot or internet gateway. This plan separates finished demo code, outstanding demonstration acceptance, features already discussed in earlier design documents, and newly specified work required for a first physical deployment.

## Priority definitions and stage gates

| Priority | Trigger | Rule |
| --- | --- | --- |
| **P0, Formnext demo** | Before the November 14 code freeze and November 17–20 show | Only disposable-VM rehearsal, release evidence, rollback/teardown and documentation. No real hardware topology changes. |
| **P1, physical-deployment foundations** | Before enabling a real guest interface or a shared-segment physical pilot | Boot-safe ownership, verified station attachment, guard version migration and host recovery must be designed and tested first. |
| **P2, usable service and operations** | Before offering real internet access, long sessions or unattended pilots | Verified public DNS/NAT, bounded-renewal entitlement semantics, persistent redacted observability and diagnostics. |
| **P3, exploratory** | After operating constraints and demand are measured | Bandwidth fairness, additional AP profiles, HaLow-specific integration, remote fleet views and more captive-assistant UX. Not committed features. |

Priority describes *when a capability becomes necessary*, not a promise about delivery dates. The first real internet pilot cannot begin while any of its P1 and applicable P2 gates are unmet.

## What exists today

| Capability | Current state | Evidence and limitation |
| --- | --- | --- |
| Strict nftables deny guard, timed allow sets and readback | **Implemented; disposable kernel CI verified** | [Formnext design](formnext-design.md), [integration evidence](formnext-integration.md), [CI 42021197054](https://github.com/thetechbenders/portcullis/actions/runs/42021197054). Not a physical network guarantee. |
| Controller, bounded grant/revoke, conntrack cleanup, failed-start isolation | **Implemented; disposable tests verified** | \`internal/controller\`, \`internal/gateway\`, \`tests/netns/e2e.sh\`. Kernel grant maximum remains 15 minutes; restarting revokes grants. |
| Interface-bound DHCP and local DNS | **Implemented for the demo** | \`internal/dhcp\` advertises gateway DNS; \`internal/guestdns/responder.go\` handles only configured captive/demo zones, refuses external names and does not recurse. **Public DNS is not available after authorization.** |
| Guest HTTP portal, state, and local operator dashboard | **Implemented; CI and headless Chrome checked** | \`internal/portal\`, \`portcullisctl\`; native browser/operator rehearsal on the target disposable VM is **not verified**. |
| Disposable topology and kernel packet E2E | **Implemented, CI green** | \`demo/portcullis-lab.sh\`; no physical AP, managed switch, NAT or actual internet path. |
| Boot-safe physical interface enable/recovery | **Requirement discussed, not implemented** | \`docs/architecture.md\` and issue #5 prescribe boot isolation; the namespace launcher currently owns link-up and forwarding, not a physical host provisioner. |
| Trusted AP station identity | **Risk recognized, mechanism absent** | \`docs/formnext-design.md\`, issue #5; MAC+IP cloning on shared L2 still inherits authority. |
| Production NAT and post-grant public DNS | **NAT topology discussed; both absent** | \`docs/architecture.md\` mentions NAT; \`docs/formnext-design.md\` intentionally excludes it. No post-grant resolver design was found. |
| Persistent operations, packages, safe policy upgrades | **Partial intentions, no deployable contract** | Early architecture mentions events; current diagnostics are demo-scoped. No version-aware guard migration or published supported ARM64 installer. |

Historical phase documents and original handoffs preserve their design-time claims and may describe components as “planned” even when the merged demo has since implemented them. Use this document for **planning state**, the current source tree and CI for **implementation evidence**, and the runbook for **demo procedure**.

## M0: Finish the disposable Formnext demonstration (P0)

**Existing issues:** [#4, release gates](https://github.com/thetechbenders/portcullis/issues/4); [#6, portal UX](https://github.com/thetechbenders/portcullis/issues/6); see also [#9, isolation reporting](https://github.com/thetechbenders/portcullis/issues/9).

**Implemented:** merged PR #8, kernel grant/deny tests, browser HTTP/CSRF checks, headless Chrome denied-page render, operator revoke/reset, kernel expiry, fail-start mutation tests, namespace launcher lifecycle and offline fallback documentation.

**Still to demonstrate, not presumed complete:**
- [ ] On the **actual disposable Formnext VM**, test native Chromium and Firefox with normal \`portal.localhost\` resolution, guest request/release and destination access before/during/after grants.
- [ ] Rehearse dashboard revoke/reset and kernel-set readback, SIGKILL followed by kernel-only expiry, restart and full teardown. Capture an operator-readable result and a fallback recording.
- [ ] Check legacy iptables and nft-visible conflicting rules, verify the appropriate isolation/attestation state, and preserve management access. Make changes only in that disposable environment.
- [ ] Record release candidate, matching CI artifact/commit, independent review disposition, teardown result and demo limitations before the November 14 freeze.

**Gate:** complete #4's *actual* release criteria, not merely check every box because a CI job is green. Nothing in M0 authorizes installation on Hephaestus, UniFi/GL.iNet or an uncontrolled physical LAN.

## M1: Safe first physical-deployment substrate (P1)

These tracks make the security claims meaningful beyond a disposable namespace:

| Workstream | Tracker | What changes relative to today's plan | Acceptance gate |
| --- | --- | --- | --- |
| Boot/interface ownership and reproducible deployment | [#10](https://github.com/thetechbenders/portcullis/issues/10) | Turns the previously **stated** boot/reload requirement in #5 into a host-specific service, interface and rollback contract; includes opt-in ARM64 packaging. | Cold boot, late controller start, firewall reload and rollback never expose guests before verified guard readiness; independent management remains available. |
| Trusted AP attachment and association revocation | [#11](https://github.com/thetechbenders/portcullis/issues/11) | Specifies the missing trusted AP/port event mechanism behind the already recognized MAC+IP cloning risk. | Proven attachment evidence and revoke-on-disconnect; no authorization based solely on MAC, DHCP or a self-reported station event. |
| Version-aware guard migrations | [#12](https://github.com/thetechbenders/portcullis/issues/12) | **Newly identified** gap: exact attestation across schema upgrades and rollback. | Old/new binaries and policies fail closed across offline migration, interruption and downgrade; never use whole-table live replacement. |

**Related existing coverage:**
- [#5](https://github.com/thetechbenders/portcullis/issues/5) remains the parent security-contract tracker for controller ownership, source-of-truth client identity, and testing. Its demo enforcement requirements are implemented, but reboot/real-host guarantees are not.
- [#9](https://github.com/thetechbenders/portcullis/issues/9) records the isolation-outcome requirement. The merged demo distinguishes confirmed/unconfirmed link-down and repeatedly checks it; external/physical isolation acceptance remains open.
- **OWE** provides individualized link encryption on open Wi-Fi; it **does not** prove authenticated long-lived station identity. AP association events should revoke or invalidate, not independently grant.

**Gate:** an independently approved topology/management rollback plan, safe boot and isolation evidence on a disposable VM, trustworthy AP identity evidence, and an explicitly authorized real-hardware test. No live guest port is to be enabled merely because M0 passed.

## M2: Real internet access and sustained sessions (P2)

| Workstream | Tracker | Status and design boundary | Acceptance gate |
| --- | --- | --- | --- |
| Authorized public DNS + IPv4 forwarding/NAT | [#13](https://github.com/thetechbenders/portcullis/issues/13) | Public names currently fail at the static DNS responder. NAT was a conceptual topology item, **not** an implementation plan. Decide on the postgrant resolver model and add any NAT only through an attested, versioned, Portcullis-owned path. | Before granting, no external DNS or internet; while verified granted, both work; revoke/expiry/crash stop access, protected networks stay denied and no free resolver appears. Depends on #12. |
| Longer user entitlement, short kernel grant | [#14](https://github.com/thetechbenders/portcullis/issues/14) | **Newly specified**: keep kernel authority ≤15 minutes, but allow an independently validated longer session through guarded renewal. Do not restore grants automatically after a crash/reboot. | Multiple renewals maintain a valid session without bypassing lease/attachment and attestation checks; loss of controller still causes kernel-only expiry. Depends on #11. |
| Operator health, durable evidence and diagnostics | [#15](https://github.com/thetechbenders/portcullis/issues/15) | Early privacy-aware event logging was mentioned, but there is no deployment-grade retention/alert/diagnostics contract. | Redacted persistent events, actionable isolation alerts and read-only bundles permit recovery without leaking tokens or mutating policy. Needed before unattended pilots. |

DNS and NAT are deliberately not coupled to a third-party hotspot implementation. Select a design only after its preauthorization bypass and policy-upgrade effects have been tested. Longer entitlements are not a payment/account system.

## P3 candidates and explicit non-goals

**Explore later, no new implementation issues yet:** static CAKE/FQ-CoDel bandwidth fairness under measured constrained uplinks (including HaLow); hardware-specific radio provisioning; AP fleet management; native captive-portal advertisement; localization/accessibility beyond the current portal; richer remote fleet visibility. Require evidence of need, hardware constraints and attack surface before promoting any to P1/P2.

**Not product requirements now:** Stripe, crypto, paid tiers, accounts, restore-grants-from-database, guest-accessible administration and importing another hotspot's firewall/installer architecture. Plain HTTP captive interception is demo scope only; a future HTTPS/status API needs a separate protocol and security design rather than generic HTTPS interception.

## Decisions that must precede implementation

1. **Host network owner:** systemd-networkd/NetworkManager/firewall stack, selected physical interfaces, immutable management path, safe install and recovery rules (#10).
2. **Station trust source:** real AP/port identity and privacy constraints; OWE vs authenticated station mechanism, roaming semantics (#11).
3. **Policy schema transition:** version markers, isolation across migration, old/new compatibility and rollback command (#12).
4. **Public DNS model and NAT boundary:** where postgrant resolver traffic goes, where enforcement lives, why pregrant DNS cannot tunnel (#13).
5. **Session policy:** entitlement lifetime, renewal timing, lease/attachment bounds and whether any non-authorizing intent survives restart (#14).
6. **Operational evidence:** event retention/redaction, health states, artifact provenance, bundle and alert limits (#15).

No implementation should assume these decisions have already been made.

## Sources, provenance and update discipline

This plan was informed by a November 5 comparative Meshlink/Portcullis audit summary supplied by the project owner. **The complete local audit report was not present in the connected GitHub repository**, so external Meshlink implementation and security assertions are not treated here as independently established facts. The proposed gaps were instead cross-checked against Portcullis's merged source, README, architecture/design docs, open issues #4–#6/#9 and PR #8 history. Absence means **“no concrete implementation/roadmap mechanism found in those sources,”** not proof that nobody has ever discussed the feature.

Keep issue ownership non-overlapping; update each milestone only after exact code/CI and, where applicable, disposable-VM or physical-hardware evidence. Preserve immutable short-lived kernel authority and fail-closed isolation. A new hardware milestone, privileged deployment or merge always needs separate authorization.
