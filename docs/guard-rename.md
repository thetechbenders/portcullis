# Guard behavior across guest interface renames

**Scope: the full Formnext `inet portcullis_guard` only.** This change does not authorize physical Pi activation and does not establish safe handling of USB removal/re-enumeration.

The full guard's hooked INPUT and FORWARD chains intentionally retain `policy accept` for unrelated host traffic. Previously the three terminal guest DROP rules matched `iifname` or `oifname`, which no longer matched after the guest netdevice was renamed. A packet could fall through those chains.

The full guard now captures the existing guest netdevice's positive Linux ifindex before bootstrap/startup. Missing devices/invalid indexes fail guard validation. Guest-facing *authorization* matches require both the configured interface **name** and its pinned index. Terminal guest DROP rules are paired: one matches the pinned index, and a second matches the configured name. Thus traffic on either the original device or a different device using the reserved guest name is denied unless it satisfies the exact authorized rule. For the **same** renamed netdevice, name-based accepts stop matching while index-bound drops remain effective. A different interface acquiring the old guest name cannot satisfy the indexed allow rules, and its traffic is caught by the complementary name-based DROP rules. The renderer, strict nft JSON verifier and associated fixtures use one rule specification. Ordinary `nft -j` may render an existing ifindex as its current name, even though the rule is installed against an index.

The disposable end-to-end suite renames the original guest netdevice and verifies guest INPUT, outbound FORWARD and inbound FORWARD drops using packet-delivery oracles and corresponding counters. It also assigns the vacated guest name to an unrelated NIC and verifies the complementary name-based INPUT drop. Both interfaces are restored before the controller starts. Those tests are **not** physical hardware acceptance.

## Still unsafe for unattended physical use

- A removed/re-enumerated USB NIC gets a **different ifindex**, which the old index-bound DROP rules may not match. The complementary name-based rules still deny the configured guest name, but **do not protect unknown replacement names**. Under base-chain `policy accept`, this requires an independent early-boot/hotplug policy keeping new devices DOWN, manager-excluded, and unable to exchange unauthorized packets until a freshly verified guard is installed. Replug is **not fixed** by this PR.
- The separate historical Phase 2 deny-only renderer (`internal/enforce/baseline.go`) remains name-bound and **lab-only**. Do not substitute it for this full guard during physical activation.
- The pinned index is read from the local kernel at construction, not independently authenticated physical identity. Live physical parent/MAC/driver ownership, manager races, bypass paths, host OUTPUT, boot persistence and management recovery are separate unverified gates.
- A renamed guest may prevent the name-based link failsafe from bringing the original interface DOWN. The index-based guard is a narrower packet protection, not evidence of a completed physical shutdown. Unknown or modified packet paths must still fail the hardware gate.

**No installation, network state mutation or Pi access is performed by this change.** Continue to use only disposable CI namespaces for packet testing until a separate operator-authorized isolated pilot meets the physical ownership contract.
