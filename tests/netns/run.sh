#!/usr/bin/env bash
# Destructive ONLY inside disposable namespaces. Run on an ephemeral CI runner.
# Requires root, iproute2, nftables, ping, python3, and the compiled policy CLI.
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo "Must run as root on a disposable test runner" >&2
  exit 2
fi
if (( $# != 1 )) || [[ ! -x "$1" ]]; then
  echo "Usage: sudo bash tests/netns/run.sh /absolute/path/to/portcullis-policy" >&2
  exit 2
fi
bin="$1"
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

echo "Checking packets can route in the fixture before firewall is installed"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_allow ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
expect_allow ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:205::2

"$bin" -guest guest0 > "$tmp/baseline.nft"
ip netns exec "$gw" nft -c -f "$tmp/baseline.nft"
ip netns exec "$gw" nft -f "$tmp/baseline.nft"

echo "Checking fail-closed baseline for INPUT, FORWARD, IPv4, IPv6"
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_block ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:203::1
expect_block ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
expect_block ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:205::2
# Other ingress should not be collateral damage.
expect_allow ip netns exec "$wan" ping -n -c 1 -W 2 198.18.0.1

# Replace the policy ONLY in this throwaway namespace. Never use this test
# source-IP fixture as a production identity/authorization mechanism.
ip netns exec "$gw" nft delete table inet portcullis_guard
"$bin" -guest guest0 -uplink uplink0 -test-fixture-timed-allow > "$tmp/timed.nft"
ip netns exec "$gw" nft -c -f "$tmp/timed.nft"
ip netns exec "$gw" nft -f "$tmp/timed.nft"
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
printf 'add element inet portcullis_guard test_allow_v4 { 10.203.0.2 timeout 12s }\n' > "$tmp/allow.nft"
ip netns exec "$gw" nft -f "$tmp/allow.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 10.204.0.2
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 10.203.0.1
expect_block ip netns exec "$guest" ping -6 -n -c 1 -W 2 2001:db8:204::2
ip -n "$guest" addr add 10.203.0.3/24 dev eth0
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 -I 10.203.0.3 198.18.0.2

echo "Checking explicit revocation terminates an existing TCP stream"
ip netns exec "$wan" python3 "$root/tests/netns/tcp_fixture.py" server --ready "$tmp/server.ready" &
server_pid="$!"
wait_for_file "$tmp/server.ready"
ip netns exec "$guest" python3 "$root/tests/netns/tcp_fixture.py" client --ready "$tmp/client.ready" --trigger "$tmp/revoke.now" --result "$tmp/client.result" &
client_pid="$!"
wait_for_file "$tmp/client.ready"
printf 'delete element inet portcullis_guard test_allow_v4 { 10.203.0.2 }\n' > "$tmp/revoke.nft"
ip netns exec "$gw" nft -f "$tmp/revoke.nft"
touch "$tmp/revoke.now"
wait "$client_pid" || fail "TCP revocation client failed"
client_pid=""
[[ "$(cat "$tmp/client.result")" == "blocked" ]] || fail "established TCP survived revocation"
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "Checking kernel timeout expires a grant without any userspace daemon"
printf 'add element inet portcullis_guard test_allow_v4 { 10.203.0.2 timeout 3s }\n' > "$tmp/short.nft"
ip netns exec "$gw" nft -f "$tmp/short.nft"
expect_allow ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2
sleep 4
expect_block ip netns exec "$guest" ping -n -c 1 -W 2 198.18.0.2

echo "PASS: isolated default-deny, IPv4/IPv6, timed grant, protected LAN, TCP revocation"
