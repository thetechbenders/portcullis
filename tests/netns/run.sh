#!/usr/bin/env bash
# Destructive ONLY inside disposable namespaces. Run on an ephemeral CI runner.
# Requires root, iproute2, nftables, ping, python3, and the compiled policy CLI.
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo "Must run as root on a disposable test runner" >&2
  exit 2
fi
if (( $# != 2 )) || [[ ! -x "$1" ]] || [[ ! -x "$2" ]]; then
  echo "Usage: sudo bash tests/netns/run.sh /path/to/normal-policy /path/to/netnslab-policy" >&2
  exit 2
fi
bin="$1"
labbin="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
guest="pcguest$$"
gw="pcgw$$"
wan="pcwan$$"
lan="pclan$$"
server_pid=""
client_pid=""
udp_server_pid=""
udp_client_pid=""
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$client_pid" ]]; then kill "$client_pid" 2>/dev/null || :; wait "$client_pid" 2>/dev/null || :; fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || :; wait "$server_pid" 2>/dev/null || :; fi
  if [[ -n "$udp_server_pid" ]]; then kill "$udp_server_pid" 2>/dev/null || :; wait "$udp_server_pid" 2>/dev/null || :; fi
  if [[ -n "$udp_client_pid" ]]; then kill "$udp_client_pid" 2>/dev/null || :; wait "$udp_client_pid" 2>/dev/null || :; fi
  if (( status != 0 )); then
    echo "=== fixture diagnostics ===" >&2
    ip -n "$gw" addr show >&2 || :
    ip -n "$guest" -6 neigh show >&2 || :
    ip netns exec "$gw" nft -a list ruleset >&2 || :
  fi
  for ns in "$guest" "$gw" "$wan" "$lan"; do
    ip netns del "$ns" 2>/dev/null || :
  done
  rm -rf -- "$tmp"
  exit "$status"
}
trap cleanup EXIT

for cmd in ip nft ping python3 sysctl timeout; do
  command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }
done

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_allow() {
  timeout 6s "$@" >/dev/null 2>&1 || fail "expected packet delivery: $*"
}
expect_block() {
  if timeout 6s "$@" >/dev/null 2>&1; then
    fail "guest bypass: $*"
  fi
}
drop_count() {
  local table="$1" chain="$2" label="$3"
  ip netns exec "$gw" nft -j list chain inet "$table" "$chain" | python3 -c '
import json, sys
label = sys.argv[1]
rules = [x["rule"] for x in json.load(sys.stdin)["nftables"] if "rule" in x]
matched = [r for r in rules if r.get("comment") == label]
if len(matched) != 1:
    raise SystemExit("expected exactly one drop rule labelled " + label)
expr = matched[0].get("expr", [])
if not any("drop" in x for x in expr):
    raise SystemExit("labelled rule does not drop: " + label)
counters = [x["counter"]["packets"] for x in expr if "counter" in x]
if len(counters) != 1:
    raise SystemExit("expected one counter for " + label)
print(int(counters[0]))
' "$label"
}
expect_drop() {
  local table="$1" chain="$2" label="$3" before after
  shift 3
  before="$(drop_count "$table" "$chain" "$label")"
  expect_block "$@"
  after="$(drop_count "$table" "$chain" "$label")"
  (( after > before )) || fail "no packet counted by $table/$chain/$label: $* ($before -> $after)"
}
# Return success only when the destination namespace actually receives
# the one-way UDP datagram. No echo response or reverse route is involved.
udp_delivered() {
  local receiver="$1" target="$2" sender="$3" marker="$tmp/udp-$RANDOM.ready" pid
  ip netns exec "$receiver" python3 "$root/tests/netns/udp_probe.py" listen "$target" --ready "$marker" &
  pid=$!
  wait_for_file "$marker"
  ip netns exec "$sender" python3 "$root/tests/netns/udp_probe.py" send "$target"
  if wait "$pid"; then
    rm -f "$marker"
    return 0
  fi
  rm -f "$marker"
  return 1
}
wait_for_file() {
  local file="$1"
  for _ in {1..100}; do
    [[ -e "$file" ]] && return 0
    sleep 0.1
  done
  fail "timeout waiting for $file"
}

# Every link is created INSIDE gateway namespace; no physical NIC touched.
for ns in "$guest" "$gw" "$wan" "$lan"; do ip netns add "$ns"; done
ip -n "$gw" link add guest0 type veth peer name guestpeer
ip -n "$gw" link set guestpeer netns "$guest"
ip -n "$guest" link set guestpeer name eth0
ip -n "$gw" link add uplink0 type veth peer name wanpeer
ip -n "$gw" link set wanpeer netns "$wan"
ip -n "$wan" link set wanpeer name eth0
ip -n "$gw" link add lan0 type veth peer name lanpeer
ip -n "$gw" link set lanpeer netns "$lan"
ip -n "$lan" link set lanpeer name eth0
for ns in "$guest" "$gw" "$wan" "$lan"; do ip -n "$ns" link set lo up; done
for interface in guest0 uplink0 lan0; do ip -n "$gw" link set "$interface" up; done
for ns in "$guest" "$wan" "$lan"; do ip -n "$ns" link set eth0 up; done

ip -n "$gw" addr add 10.203.0.1/24 dev guest0
ip -n "$guest" addr add 10.203.0.2/24 dev eth0
ip -n "$gw" addr add 198.18.0.1/24 dev uplink0
ip -n "$wan" addr add 198.18.0.2/24 dev eth0
ip -n "$gw" addr add 10.204.0.1/24 dev lan0
ip -n "$lan" addr add 10.204.0.2/24 dev eth0
ip netns exec "$gw" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$gw" sysctl -qw net.ipv6.conf.all.forwarding=1
ip -n "$gw" -6 addr add 2001:db8:203::1/64 dev guest0
ip -n "$guest" -6 addr add 2001:db8:203::2/64 dev eth0
ip -n "$gw" -6 addr add 2001:db8:204::1/64 dev uplink0
ip -n "$wan" -6 addr add 2001:db8:204::2/64 dev eth0
ip -n "$gw" -6 addr add 2001:db8:205::1/64 dev lan0
ip -n "$lan" -6 addr add 2001:db8:205::2/64 dev eth0
ip -n "$guest" route add default via 10.203.0.1
ip -n "$guest" -6 route add default via 2001:db8:203::1
ip -n "$wan" route add 10.203.0.0/24 via 198.18.0.1
ip -n "$wan" -6 route add 2001:db8:203::/64 via 2001:db8:204::1
ip -n "$lan" route add 10.203.0.0/24 via 10.204.0.1
ip -n "$lan" -6 route add 2001:db8:203::/64 via 2001:db8:205::1

# Linux performs IPv6 duplicate-address detection asynchronously. Wait for
# addresses to leave tentative state before the first routed packet test.
sleep 3
# The guest must continue resolving its IPv6 default gateway even when
# the guest INPUT firewall blocks IPv6 neighbour solicitations.
gwmac="$(ip netns exec "$gw" cat /sys/class/net/guest0/address)"
ip -n "$guest" -6 neigh replace 2001:db8:203::1 lladdr "$gwmac" dev eth0 nud permanent

echo "Checking packets can route in the fixture before firewall is installed"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_allow ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:203::1
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_allow ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
expect_allow ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:205::2
# Confirm one-way UDP delivery prior to loading nft rules.
udp_delivered "$wan" 198.18.0.2 "$guest" || fail "missing guest->WAN UDP precondition"
udp_delivered "$guest" 10.203.0.2 "$wan" || fail "missing WAN->guest UDP precondition"
# Reverse-direction preconditions must succeed without nft filtering.
expect_allow ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_allow ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_allow ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_allow ip netns exec "$lan" ping -6 -n -c 1 -W 2 2001:db8:203::2

"$bin" -guest guest0 > "$tmp/baseline.nft"
"$bin" -guest guest0 -reconcile > "$tmp/reconcile.nft"
# In-place reconciliation must refuse missing base chains. Bootstrapping is
# separate and must happen before a guest is ever connected.
if ip netns exec "$gw" nft -f "$tmp/reconcile.nft" >/dev/null 2>&1; then
  fail "reconciler unexpectedly installed missing base chains"
fi
ip netns exec "$gw" nft -c -f "$tmp/baseline.nft"
ip netns exec "$gw" nft -f "$tmp/baseline.nft"

echo "Checking fail-closed baseline for INPUT, FORWARD, IPv4, IPv6"
expect_drop portcullis_guard guest_input guest-input ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_drop portcullis_guard guest_input guest-input ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:203::1
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:205::2
echo "Checking reverse traffic is dropped at the gateway FORWARD hook"
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$lan" ping -6 -n -c 1 -W 2 2001:db8:203::2
# One-way delivery is the decisive oracle: ping can fail only on its
# return path. A deliberately broken direction MUST be detected here.
if udp_delivered "$wan" 198.18.0.2 "$guest"; then fail "guest->WAN UDP escaped baseline"; fi
if udp_delivered "$guest" 10.203.0.2 "$wan"; then fail "WAN->guest UDP escaped baseline"; fi

echo "Mutation self-test: broken ingress and egress rules must be detected"
sed 's/oifname "guest0" counter drop comment "guest-ingress"/oifname "wrongif0" counter drop comment "guest-ingress"/' "$tmp/baseline.nft" > "$tmp/mut-ingress.nft"
ip netns exec "$gw" nft -f "$tmp/mut-ingress.nft"
# The WAN probe must now arrive, and the guest-ingress rule's counter must
# remain unchanged. A test based on aggregate FORWARD counters would miss it.
udp_delivered "$guest" 10.203.0.2 "$wan" || fail "ingress mutation failed to expose UDP bypass"
if ( expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2 ) >/dev/null 2>&1; then
  fail "ingress mutation was not rejected by its directional counter oracle"
fi
ip netns exec "$gw" nft -f "$tmp/baseline.nft"
sed 's/iifname "guest0" counter drop comment "guest-egress"/iifname "wrongif0" counter drop comment "guest-egress"/' "$tmp/baseline.nft" > "$tmp/mut-egress.nft"
ip netns exec "$gw" nft -f "$tmp/mut-egress.nft"
udp_delivered "$wan" 198.18.0.2 "$guest" || fail "egress mutation failed to expose UDP bypass"
if ( expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2 ) >/dev/null 2>&1; then
  fail "egress mutation was not rejected by its directional counter oracle"
fi
ip netns exec "$gw" nft -f "$tmp/baseline.nft"
# Other ingress should not be collateral damage.
expect_allow ip netns exec "$wan" ping -n -c 1 -W 2 198.18.0.1

echo "Checking in-place reconciliation without base-chain replacement"
# A successful repeated reconcile must preserve base-chain handles and never
# leave duplicate rules. The old whole-table bootstrap remains lab-only.
ip netns exec "$gw" nft -c -f "$tmp/reconcile.nft"
ip netns exec "$gw" nft -f "$tmp/reconcile.nft"
input_handle_before="$(ip netns exec "$gw" nft -a list chain inet portcullis_guard guest_input | head -n 2)"
forward_handle_before="$(ip netns exec "$gw" nft -a list chain inet portcullis_guard guest_forward | head -n 2)"
for iteration in {1..30}; do ip netns exec "$gw" nft -f "$tmp/reconcile.nft"; done
[[ "$(ip netns exec "$gw" nft -a list chain inet portcullis_guard guest_input | head -n 2)" == "$input_handle_before" ]] || fail "input base chain replaced during reconcile"
[[ "$(ip netns exec "$gw" nft -a list chain inet portcullis_guard guest_forward | head -n 2)" == "$forward_handle_before" ]] || fail "forward base chain replaced during reconcile"
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2

echo "Checking atomic policy convergence with existing rules and stale permits"
# Reapplying must not append duplicate chains or rules.
ip netns exec "$gw" nft -c -f "$tmp/baseline.nft"
ip netns exec "$gw" nft -f "$tmp/baseline.nft"
forward_rules="$(ip netns exec "$gw" nft -j list chain inet portcullis_guard guest_forward | python3 -c 'import json,sys; print(sum("rule" in e for e in json.load(sys.stdin)["nftables"]))')"
[[ "$forward_rules" -eq 2 ]] || fail "reapply accumulated rules (forward count=$forward_rules)"
# Simulate stale broad permits in the owned table on this THROWAWAY lab.
# A guest ping must work with the deliberate bad rule, proving the test's
# stale-permit injection is capable of bypassing the baseline.
ip netns exec "$gw" nft insert rule inet portcullis_guard guest_forward iifname guest0 oifname uplink0 counter accept
ip netns exec "$gw" nft insert rule inet portcullis_guard guest_forward oifname guest0 counter accept
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
# One nft -f invocation must remove both bad permits without a gap.
ip netns exec "$gw" nft -c -f "$tmp/reconcile.nft"
ip netns exec "$gw" nft -f "$tmp/reconcile.nft"
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
forward_rules="$(ip netns exec "$gw" nft -j list chain inet portcullis_guard guest_forward | python3 -c 'import json,sys; print(sum("rule" in e for e in json.load(sys.stdin)["nftables"]))')"
[[ "$forward_rules" -eq 2 ]] || fail "stale rules survived atomic replacement"
# A broken transaction must reject the whole batch and preserve the deny.
{ cat "$tmp/reconcile.nft"; echo 'create chain inet portcullis_guard guest_forward'; } > "$tmp/invalid.nft"
if ip netns exec "$gw" nft -f "$tmp/invalid.nft" >/dev/null 2>&1; then
  fail "invalid firewall transaction was accepted"
fi
expect_drop portcullis_guard guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2

# Switch the policy ONLY in this throwaway namespace. Never use the test
# source-IP fixture as a production identity/authorization mechanism.
"$labbin" -guest guest0 -uplink uplink0 > "$tmp/timed.nft"
{ echo 'delete table inet portcullis_guard'; cat "$tmp/timed.nft"; } > "$tmp/switch.nft"
ip netns exec "$gw" nft -c -f "$tmp/switch.nft"
ip netns exec "$gw" nft -f "$tmp/switch.nft"
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
printf 'add element inet portcullis_lab test_allow_v4 { 10.203.0.2 timeout 60s }\n' > "$tmp/allow.nft"
ip netns exec "$gw" nft -f "$tmp/allow.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
# A permitted guest's return packets work only for established flows.
# Unsolicited reverse traffic and all IPv6 still hit the drop rule.
expect_drop portcullis_lab guest_forward guest-ingress ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_lab guest_forward guest-ingress ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_lab guest_forward guest-ingress ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_drop portcullis_lab guest_input guest-input ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
ip -n "$guest" addr add 10.203.0.3/24 dev eth0
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 -I 10.203.0.3 198.18.0.2

echo "Checking explicit revocation terminates an existing TCP stream"
ip netns exec "$wan" python3 "$root/tests/netns/tcp_fixture.py" server --ready "$tmp/server.ready" &
server_pid="$!"
wait_for_file "$tmp/server.ready"
ip netns exec "$guest" python3 "$root/tests/netns/tcp_fixture.py" client --ready "$tmp/client.ready" --trigger "$tmp/revoke.now" --result "$tmp/client.result" --resume "$tmp/restore.now" &
client_pid="$!"
wait_for_file "$tmp/client.ready"
printf 'delete element inet portcullis_lab test_allow_v4 { 10.203.0.2 }\n' > "$tmp/revoke.nft"
ip netns exec "$gw" nft -f "$tmp/revoke.nft"
before_revoke="$(drop_count portcullis_lab guest_forward guest-egress)"
touch "$tmp/revoke.now"
wait_for_file "$tmp/client.result"
[[ "$(cat "$tmp/client.result")" == "timeout" ]] || fail "TCP revocation did not time out"
kill -0 "$server_pid" || fail "server died during revoked interval"
[[ ! -f "$tmp/server.ready.2" ]] || fail "revoked TCP payload reached the server"
after_revoke="$(drop_count portcullis_lab guest_forward guest-egress)"
(( after_revoke > before_revoke )) || fail "no forwarded TCP packet was dropped"
# Regrant while the connection remains open; prove the SAME TCP socket can
# receive the queued server response. A failed/dead peer cannot pass.
printf 'add element inet portcullis_lab test_allow_v4 { 10.203.0.2 timeout 20s }\n' > "$tmp/restore.nft"
ip netns exec "$gw" nft -f "$tmp/restore.nft"
touch "$tmp/restore.now"
wait "$client_pid" || fail "same-socket TCP recovery failed"
client_pid=""
[[ "$(cat "$tmp/client.result")" == "recovered" ]] || fail "connection failed to recover"
[[ -f "$tmp/server.ready.2" ]] || fail "server never received the restored payload"
ip netns exec "$gw" nft -f "$tmp/revoke.nft"
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "Checking inbound UDP on an established flow after revoke and expiry"
udp_session_case() {
  local kind="$1" prefix="$tmp/udp-$1" before after
  # Test-only source-IP permission. Real deployments cannot trust source IP.
  if [[ "$kind" == "expiry" ]]; then
    ip netns exec "$gw" nft add element inet portcullis_lab test_allow_v4 '{ 10.203.0.2 timeout 5s }'
  else
    ip netns exec "$gw" nft add element inet portcullis_lab test_allow_v4 '{ 10.203.0.2 timeout 30s }'
  fi
  ip netns exec "$wan" python3 "$root/tests/netns/udp_session.py" server "$prefix" &
  udp_server_pid="$!"
  ip netns exec "$guest" python3 "$root/tests/netns/udp_session.py" client "$prefix" &
  udp_client_pid="$!"
  wait_for_file "$prefix.client-ready"
  wait_for_file "$prefix.server-ready"
  if [[ "$kind" == "expiry" ]]; then
    # Kernel expiry occurs without deleting the element from userspace.
    sleep 6
  else
    ip netns exec "$gw" nft delete element inet portcullis_lab test_allow_v4 '{ 10.203.0.2 }'
  fi
  before="$(drop_count portcullis_lab guest_forward guest-ingress)"
  touch "$prefix.trigger"
  wait_for_file "$prefix.sent"
  wait_for_file "$prefix.blocked"
  kill -0 "$udp_server_pid" || fail "UDP server died during $kind"
  after="$(drop_count portcullis_lab guest_forward guest-ingress)"
  (( after > before )) || fail "inbound UDP was not dropped after $kind"
  # The tracked UDP session remains alive, so a genuine drop must recover
  # on exactly the same guest socket if authorization is restored.
  ip netns exec "$gw" nft add element inet portcullis_lab test_allow_v4 '{ 10.203.0.2 timeout 20s }'
  touch "$prefix.resume"
  wait_for_file "$prefix.recovered"
  wait "$udp_client_pid" || fail "UDP client failed to recover after $kind"
  udp_client_pid=""
  wait "$udp_server_pid" || fail "UDP server failed after $kind"
  udp_server_pid=""
  ip netns exec "$gw" nft delete element inet portcullis_lab test_allow_v4 '{ 10.203.0.2 }'
}
udp_session_case revoke
udp_session_case expiry

echo "Checking kernel timeout expires a grant without any userspace daemon"
printf 'add element inet portcullis_lab test_allow_v4 { 10.203.0.2 timeout 3s }\n' > "$tmp/short.nft"
ip netns exec "$gw" nft -f "$tmp/short.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
sleep 4
expect_drop portcullis_lab guest_forward guest-egress ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "PASS: isolated default-deny, IPv4/IPv6, timed grant, protected LAN, TCP revocation"
