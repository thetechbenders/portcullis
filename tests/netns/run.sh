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
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$client_pid" ]]; then kill "$client_pid" 2>/dev/null || :; wait "$client_pid" 2>/dev/null || :; fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || :; wait "$server_pid" 2>/dev/null || :; fi
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
  ip netns exec "$gw" nft -j list chain inet "$1" "$2" | python3 -c '
import json, sys
data = json.load(sys.stdin)["nftables"]
print(sum(int(e["counter"]["packets"])
    for item in data for rule in [item.get("rule", {})]
    if any("drop" in e for e in rule.get("expr", []))
    for e in rule.get("expr", []) if "counter" in e))
'
}
expect_drop() {
  local table="$1" chain="$2" before after
  shift 2
  before="$(drop_count "$table" "$chain")"
  expect_block "$@"
  after="$(drop_count "$table" "$chain")"
  (( after > before )) || fail "no packet counted by $table/$chain drop: $* ($before -> $after)"
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
# Reverse-direction preconditions must succeed without nft filtering.
expect_allow ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_allow ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_allow ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_allow ip netns exec "$lan" ping -6 -n -c 1 -W 2 2001:db8:203::2

"$bin" -guest guest0 > "$tmp/baseline.nft"
ip netns exec "$gw" nft -c -f "$tmp/baseline.nft"
ip netns exec "$gw" nft -f "$tmp/baseline.nft"

echo "Checking fail-closed baseline for INPUT, FORWARD, IPv4, IPv6"
expect_drop portcullis_guard guest_input ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_drop portcullis_guard guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_drop portcullis_guard guest_input ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:203::1
expect_drop portcullis_guard guest_forward ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
expect_drop portcullis_guard guest_forward ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:205::2
echo "Checking reverse traffic is dropped at the gateway FORWARD hook"
expect_drop portcullis_guard guest_forward ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_guard guest_forward ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_guard guest_forward ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_drop portcullis_guard guest_forward ip netns exec "$lan" ping -6 -n -c 1 -W 2 2001:db8:203::2
# Other ingress should not be collateral damage.
expect_allow ip netns exec "$wan" ping -n -c 1 -W 2 198.18.0.1

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
ip netns exec "$gw" nft -c -f "$tmp/baseline.nft"
ip netns exec "$gw" nft -f "$tmp/baseline.nft"
expect_drop portcullis_guard guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_guard guest_forward ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
forward_rules="$(ip netns exec "$gw" nft -j list chain inet portcullis_guard guest_forward | python3 -c 'import json,sys; print(sum("rule" in e for e in json.load(sys.stdin)["nftables"]))')"
[[ "$forward_rules" -eq 2 ]] || fail "stale rules survived atomic replacement"

# Switch the policy ONLY in this throwaway namespace. Never use the test
# source-IP fixture as a production identity/authorization mechanism.
"$labbin" -guest guest0 -uplink uplink0 > "$tmp/timed.nft"
{ echo 'delete table inet portcullis_guard'; cat "$tmp/timed.nft"; } > "$tmp/switch.nft"
ip netns exec "$gw" nft -c -f "$tmp/switch.nft"
ip netns exec "$gw" nft -f "$tmp/switch.nft"
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
printf 'add element inet portcullis_lab test_allow_v4 { 10.203.0.2 timeout 60s }\n' > "$tmp/allow.nft"
ip netns exec "$gw" nft -f "$tmp/allow.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
# A permitted guest's return packets work only for established flows.
# Unsolicited reverse traffic and all IPv6 still hit the drop rule.
expect_drop portcullis_lab guest_forward ip netns exec "$wan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_lab guest_forward ip netns exec "$lan" ping -n -c 1 -W 2 10.203.0.2
expect_drop portcullis_lab guest_forward ip netns exec "$wan" ping -6 -n -c 1 -W 2 2001:db8:203::2
expect_drop portcullis_lab guest_input ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
ip -n "$guest" addr add 10.203.0.3/24 dev eth0
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 -I 10.203.0.3 198.18.0.2

echo "Checking explicit revocation terminates an existing TCP stream"
ip netns exec "$wan" python3 "$root/tests/netns/tcp_fixture.py" server --ready "$tmp/server.ready" &
server_pid="$!"
wait_for_file "$tmp/server.ready"
ip netns exec "$guest" python3 "$root/tests/netns/tcp_fixture.py" client --ready "$tmp/client.ready" --trigger "$tmp/revoke.now" --result "$tmp/client.result" --resume "$tmp/restore.now" &
client_pid="$!"
wait_for_file "$tmp/client.ready"
printf 'delete element inet portcullis_lab test_allow_v4 { 10.203.0.2 }\n' > "$tmp/revoke.nft"
ip netns exec "$gw" nft -f "$tmp/revoke.nft"
before_revoke="$(drop_count portcullis_lab guest_forward)"
touch "$tmp/revoke.now"
wait_for_file "$tmp/client.result"
[[ "$(cat "$tmp/client.result")" == "timeout" ]] || fail "TCP revocation did not time out"
kill -0 "$server_pid" || fail "server died during revoked interval"
[[ ! -f "$tmp/server.ready.2" ]] || fail "revoked TCP payload reached the server"
after_revoke="$(drop_count portcullis_lab guest_forward)"
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
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "Checking kernel timeout expires a grant without any userspace daemon"
printf 'add element inet portcullis_lab test_allow_v4 { 10.203.0.2 timeout 3s }\n' > "$tmp/short.nft"
ip netns exec "$gw" nft -f "$tmp/short.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
sleep 4
expect_drop portcullis_lab guest_forward ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "PASS: isolated default-deny, IPv4/IPv6, timed grant, protected LAN, TCP revocation"
